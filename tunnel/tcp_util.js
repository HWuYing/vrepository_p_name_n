const config = require('./../config');
const eventBufLen = config.eventBufLen;

const UdpUtil = require('./udp_util');
const packageManage = require('./../utils').packageManage;

class TcpUtil {


	/**
	 * tcp传输事件解包
	 * @param data
	 * @param next
	 */
	static decomEventPackage(data, next) {
		packageManage.splitMergePackage(data).map(_ => {
			next(Object.assign({}, {
				event: _.slice(0, eventBufLen).toString()
			}, UdpUtil.decomPackage(_.slice(eventBufLen))))
		});
	}

	/**
	 * tcp传输事件打包
	 * @param data
	 * @param next
	 */
	static warpEventPackage(event, hash, count, data) {
		let _event = Buffer.alloc(eventBufLen, '');
		_event.write(event);
		if (Buffer.isBuffer(hash)) data = hash;
		else data = UdpUtil.warpPackage(hash, count, data);
		return packageManage.addPackageSizeTitle(Buffer.concat([_event, data], eventBufLen + data.length));
	}
}


module.exports = exports = TcpUtil;