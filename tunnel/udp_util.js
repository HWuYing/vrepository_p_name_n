const createAseEjb = require('./../aes_ejb');
const config = require('./../config');
const splitPackageSize = config.splitPackageSize - 500;
const packageMaxDisparity = config.packageMaxDisparity;
const countBufLen = config.countBufLen;
const hashBufLen = config.hashBufLen;
const packageSize = config.packageSize;
const splitBufPackageSize = config.splitBufPackageSize;
const packageManage = require('./../utils').packageManage;

const aesEjbUdp = createAseEjb();
const writeBuf = packageManage.writeBuf;
const bufSlice = packageManage.bufSlice;

class UdpUtil {
	constructor() {
		this.map = {};
	}

	/**
	 * 拆解包
	 * @param _
	 * @param next
	 */
	static splitPackage(_, next) {
		let splitList = aesEjbUdp.encryption(_, splitPackageSize);
		let write = writeBuf([splitBufPackageSize, packageSize]);
		write(splitList.length, splitBufPackageSize);
		write(_.length, packageSize);
		splitList.map((__, index) => {
			let _index = Buffer.alloc(4);
			_index.write(index.toString());
			next(Buffer.concat([write.buf, _index, __], write._len + 4 + __.length));
		});
		return splitList.length;
	}

	/**
	 * 获取被拆解包的参数
	 * @param _
	 * @returns {{splitLength: Number, index: Number, pageSize: Number, data: *}}
	 */
	static getSplitPackageParam(_) {
		let slice = bufSlice(_);
		let splitLength = parseInt(slice(splitBufPackageSize).toString());
		let pageSize = parseInt(slice(packageSize).toString());
		let index = parseInt(slice(4).toString());
		let data = aesEjbUdp.decryption(_.slice(splitBufPackageSize + packageSize + 4));
		return {splitLength, index, pageSize, data};
	}

	/**
	 * 合并被拆解的包
	 * @param _
	 * @returns {*}
	 */
	static mergePackage(_) {
		let {splitLength, index, pageSize, data} = UdpUtil.getSplitPackageParam(_);
		let mergeList = new Array(splitLength);
		mergeList[index] = data;
		if (pageSize == data.length) return data;
		return (__) => {
			let _data = UdpUtil.getSplitPackageParam(__);
			if (_data.index == splitLength - 1) {
				if (!_data.data) {
					console.log(`==========mergePackage index:${index} splitLength:${splitPackageSize}================`);
					console.log(mergeList);
				}
				mergeList[_data.index] = _data.data || Buffer.alloc(0);
				return Buffer.concat(mergeList);
			} else {
				mergeList[_data.index] = _data.data;
				return false;
			}
		}
	}

	/**
	 * 数据解包 udp
	 * @param data
	 * @returns {{hash, count: Number, data: (Array.<T>|string|Blob|ArrayBuffer|*)}}
	 */
	static decomPackage(data) {
		let slice = bufSlice(data);
		let hash = slice(hashBufLen).toString();
		let count = parseInt(slice(countBufLen).toString());
		data = data.slice(hashBufLen + countBufLen);
		return {hash, count, data};
	}

	/**
	 * 数据打包 udp
	 * @param hash
	 * @param count
	 * @param data
	 * @returns {Array.<T>|string|*}
	 */
	static warpPackage(hash, count, data) {
		let write = writeBuf([countBufLen, hashBufLen]);
		write(hash, hashBufLen);
		write(count || 0, countBufLen);
		data = data || Buffer.alloc(0, '');
		return Buffer.concat([write.buf, data], write._len + data.length);
	}

	add(key, socket) {
		let map = this.map;
		if (!map.hasOwnProperty(key)) map[key] = {
			socket: socket,
			writeVernier: 0,
			maxCount: -1,
			merge: undefined,
			judgeDiscardPackage: undefined,
			firstWritUdp: undefined,
			writePackageList: {},
		};
		return map[key];
	}

	get(key) {
		return this.map[key];
	}

	writePushPackage(key, count, data) {
		this.get(key).writePackageList[count] = data;
		return this;
	}

	removeWritePackage(key, count) {
		// console.log('===========remove==============');
		// console.log(key,count);
		delete this.get(key).writePackageList[count];
		// console.log(this.get(key).writePackageList);
	}

	createJudgeDiscardPackage(vernier, obj) {
		let si = setTimeout(() => {
			if (vernier == obj.writeVernier) obj.socket.error(new Error('存在丢包'));
		}, 3000);
		return () => {
			clearTimeout(si);
			si = null;
		}
	}

	write(key, count, data) {
		let obj = this.get(key);
		if (!obj) return;
		let nextData;
		let merge;
		if (obj.writeVernier == count) {
			if (!obj.merge) merge = obj.merge = UdpUtil.mergePackage(data);
			else merge = obj.merge(data);
			if (Buffer.isBuffer(merge)) {
				// console.log(`=================merge ${key} ${count}==============`);
				// console.log(merge.length);
				obj.socket.write(merge);
				obj.merge = undefined;
			}
			if (obj.judgeDiscardPackage) {
				obj.judgeDiscardPackage();
				obj.judgeDiscardPackage = undefined;
			}
			obj.writeVernier++;
			try {
				this.removeWritePackage(key, count);
			} catch (e) {
				console.log(`${e}`);
			}
			if (nextData = obj.writePackageList[++count] && nextData) this.write(key, count, nextData);
		} else this.writePushPackage(key, count, data);
		if (obj.writeVernier + packageMaxDisparity < count && obj.judgeDiscardPackage) {
			obj.judgeDiscardPackage = this.createJudgeDiscardPackage(obj.writeVernier, obj);
		}
	}

	createFirstWritUdp(key, buf, udpServer) {
		let _cache = [], count = 0;
		let splitLength = UdpUtil.splitPackage(buf, _ => _cache.push(UdpUtil.warpPackage(key, count++, _)));
		this.get(key).firstWritUdp = () => _cache.map(_ => udpServer(_));
		return splitLength;
	}

	firstWriteUdp(key) {
		this.get(key).firstWritUdp();
		this.get(key).firstWritUdp = undefined;

	}

	end(key, maxCount) {
		let obj = this.get(key);
		if (!obj || (obj && obj.socket.ended)) return;
		obj.maxCount = parseInt(maxCount || -1);
		if (obj.maxCount == -1 || (obj.maxCount != -1 && obj.maxCount <= obj.writeVernier)) this.destroy(key);
	}

	error(key) {
		this.destroy(key);
	}

	destroy(key) {
		let obj = this.get(key);
		if (!obj) return;
		if (!obj.socket.ended) obj.socket.end();

		delete this.map[key];
	}
}


module.exports = exports = UdpUtil;