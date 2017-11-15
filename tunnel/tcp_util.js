const createAseEjb = require('./../aes_ejb');
const config = require('./../config');
const eventBufLen = config.eventBufLen;

const UdpUtil = require('./udp_util');

const packageManage = require('./../utils').packageManage;
const writeBuf = packageManage.writeBuf;
const bufSlice = packageManage.bufSlice;

const aesEjbTcp = createAseEjb();

class TcpUtil {
	static decomEventPackage(data, next) {
		packageManage.splitMergePackage(data).map(_ => {
			next(Object.assign({}, {
				event: _.slice(0, eventBufLen).toString()
			}, UdpUtil.decomPackage(_.slice(eventBufLen))))
		});
	}

	static warpEventPackage(event, hash, count, data) {
		let _event = Buffer.alloc(eventBufLen, '');
		_event.write(event);
		if (Buffer.isBuffer(hash)) data = hash;
		else data = UdpUtil.warpPackage(hash, count, data);
		return packageManage.addPackageSizeTitle(Buffer.concat([_event, data], eventBufLen + data.length));
	}
}


module.exports = exports = TcpUtil;