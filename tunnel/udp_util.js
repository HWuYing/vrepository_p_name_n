const aseEjb = require('./../aes_ejb')();
const config = require('./../config');
const splitPackageSize = config.splitPackageSize - 500;
const packageMaxDisparity = config.packageMaxDisparity;
const countBufLen = config.countBufLen;
const hashBufLen = config.hashBufLen;
const packageSize = config.packageSize;
const eventBufLen = config.eventBufLen;
const splitBufPackageSize = config.splitBufPackageSize;
const packageManage = require('./../utils').packageManage;

const writeBuf = packageManage.writeBuf;
const bufSlice = packageManage.bufSlice;

class UdpUtil {
	constructor() {
		this.map = {};
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

	splitPackage(_, next) {
		let splitList = aseEjb.encryption(_, splitPackageSize);
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

	getSplitPackageParam(_) {
		let slice = bufSlice(_);
		let splitLength = parseInt(slice(splitBufPackageSize).toString());
		let pageSize = parseInt(slice(packageSize).toString());
		let index = parseInt(slice(4).toString());
		let data = aseEjb.decryption(_.slice(splitBufPackageSize + packageSize + 4));
		return {splitLength, index, pageSize, data};
	}

	mergePackage(_) {
		let {splitLength, index, pageSize, data} = this.getSplitPackageParam(_);
		let mergeList = new Array(splitLength);
		mergeList[index] = data;
		if (pageSize == data.length) return data;
		return (__) => {
			let _data = this.getSplitPackageParam(__);
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

	decomPackage(data) {
		let slice = bufSlice(data);
		let hash = slice(hashBufLen).toString();
		let count = parseInt(slice(countBufLen).toString());
		data = data.slice(hashBufLen + countBufLen);
		return {hash, count, data};
	}

	warpPackage(hash, count, data) {
		let write = writeBuf([countBufLen, hashBufLen]);
		write(hash, hashBufLen);
		write(count || 0, countBufLen);
		data = data || Buffer.alloc(0, '');
		return Buffer.concat([write.buf, data], write._len + data.length);
	}

	decomEventPackage(data, next) {
		// console.log(`============decomEventPackage=============`)
		// console.log(data.toString());
		packageManage.splitMergePackage(data).map(_ => {
			next(Object.assign({}, {
				event: _.slice(0, eventBufLen).toString()
			}, this.decomPackage(_.slice(eventBufLen))))
		});
	}

	warpEventPackage(event, hash, count, data) {
		let _event = Buffer.alloc(eventBufLen, '');
		_event.write(event);
		if (Buffer.isBuffer(hash)) data = hash;
		else data = this.warpPackage(hash, count, data);
		return packageManage.addPackageSizeTitle(Buffer.concat([_event, data], eventBufLen + data.length));
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
			if (!obj.merge) merge = obj.merge = this.mergePackage(data);
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
			if (nextData = obj.writePackageList[++count]) this.write(key, count, nextData);
		} else this.writePushPackage(key, count, data);
		if (obj.writeVernier + packageMaxDisparity < count && obj.judgeDiscardPackage) {
			obj.judgeDiscardPackage = this.createJudgeDiscardPackage(obj.writeVernier, obj);
		}
	}

	createFirstWritUdp(key, buf, udpServer) {
		let _cache = [], count = 0;
		let splitLength = this.splitPackage(buf, _ => _cache.push(this.warpPackage(key, count++, _)));
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


module.exports = exports = function () {
	return new UdpUtil();
};