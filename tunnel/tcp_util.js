const createAseEjb = require('./../aes_ejb');
const config = require('./../config');
const eventBufLen = config.eventBufLen;

const packageManage = require('./../utils').packageManage;
const writeBuf = packageManage.writeBuf;
const bufSlice = packageManage.bufSlice;

const aesEjbTcp = createAseEjb();

class TcpUtil {
	static decomEventPackage(data, next) {
		// console.log(`============decomEventPackage=============`)
		// console.log(data.toString());
		packageManage.splitMergePackage(data).map(_ => {
			next(Object.assign({}, {
				event: _.slice(0, eventBufLen).toString()
			}, this.decomPackage(_.slice(eventBufLen))))
		});
	}

	static warpEventPackage(event, hash, count, data) {
		let _event = Buffer.alloc(eventBufLen, '');
		_event.write(event);
		if (Buffer.isBuffer(hash)) data = hash;
		else data = this.warpPackage(hash, count, data);
		return packageManage.addPackageSizeTitle(Buffer.concat([_event, data], eventBufLen + data.length));
	}
}


module.exports = exports = function () {
	return new TcpUtil();
};