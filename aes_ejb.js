const crypto = require('crypto');
const util = require('./utils');
const {KEY_RESET, splitPackageSize} = require('./config');
const packageConfig = {
	keyLength: 4,
	keySize: 64,
	packageSize: 8,
	maxPageSize: splitPackageSize,
	titleBaoWenLength: 80,
};

const {writeBuf, bufSlice} = util.packageManage;

const getSerialNumber = (() => {
	const serialList = [];
	for (let i = 0; i < 100; i++) serialList.push(i % 10);
	return (serialLength) => {
		let serialNumber = '';
		for (let i = 0; i < serialLength; i++) serialNumber += serialList[parseInt(Math.random() * 1000) % 100];
		return serialNumber.slice(0, serialLength);
	};
})();

const getPassword = (() => {
	const keyList = (() => {
		let key = '', i;
		let fromCharCode = String.fromCharCode;
		for (i = 0; i < 10; i++) key += i.toString();
		for (i = 0; i < 26; i++) key += fromCharCode(i + 65) + fromCharCode(i + 97);
		key += '~!@#$%^&*(()_+-=';
		return key;
	})();
	return (serialNumber) => serialNumber.split('').map((number, index) => keyList[(parseInt(number) + index * 64) % keyList.length]).join('');
})();

const titleBaoWen = (() => {
	const length = 32;
	const {packageSize, keyLength, keySize, titleBaoWenLength} = packageConfig;
	const titleLength = packageSize + keySize + keyLength;
	const config = mergeConfig({
		passwordLength: length,
		serialNumber: '01234567890123456789012345678901',
		algorithm: `aes-${length * 8}-ecb`
	});
	const password = getPassword(config.serialNumber);
	const {algorithm, iv} = config;

	function baoWenEncryption(_data) {
		let cipher = crypto.createCipheriv(algorithm, password, iv);
		let _1 = cipher.update(_data);
		let _2 = cipher.final();
		return Buffer.concat([_1, _2], _1.length + _2.length);
	}

	function baoWenDecryption(data) {
		let decipher = crypto.createDecipheriv(algorithm, password, iv);
		let _1 = decipher.update(data);
		let _2 = decipher.final();
		return Buffer.concat([_1, _2], _1.length + _2.length);
	}

	function warpTitle(buf, key) {
		let _writeBuf = writeBuf(titleLength);
		_writeBuf(buf.length, packageSize); //写入数据字节长度
		_writeBuf(key.length, keyLength); //写入序列号的长度
		_writeBuf(key, keySize); //写入序列号
		let d_buf = baoWenEncryption(_writeBuf.buf);
		return [d_buf, titleBaoWenLength];
	}

	function decomTitle(buf) {
		let titleBaoWenSlice = bufSlice(baoWenDecryption(buf.slice(0, titleBaoWenLength)));
		let _packageSize = parseInt(titleBaoWenSlice(packageSize).toString());
		let _keyLength = parseInt(titleBaoWenSlice(keyLength).toString());
		let key = titleBaoWenSlice(_keyLength).toString();
		let data = buf.slice(titleBaoWenLength, titleBaoWenLength + _packageSize);
		return {
			packageLength: _packageSize,
			keyLength: _keyLength,
			titleBaoWenLength,
			key,
			data
		};
	}

	return {
		warpTitle,
		decomTitle
	}
})();

/**
 * 加密
 * @param key
 * @param iv
 * @returns {function(*=)}
 */
function factoryEncryption(config) {
	const {algorithm, serialNumber, iv} = config;
	const password = getPassword(serialNumber);
	return function (data, packageSize) {
		let writeList = [], _buf = data;
		packageSize = packageSize || packageConfig.maxPageSize;
		if (data.length > packageSize) {
			while (_buf.length > packageSize) {
				writeList.push(_buf.slice(0, packageSize));
				_buf = _buf.slice(packageSize);
			}
			_buf.length != 0 && writeList.push(_buf);
		} else writeList = [data];
		return writeList.map((_data) => {
			let cipher = crypto.createCipheriv(algorithm, password, iv);
			let _1 = cipher.update(_data);
			let _2 = cipher.final();
			return setKeyAndLength(Buffer.concat([_1, _2], _1.length + _2.length), serialNumber)
		});
	};
}

/**
 * 解密
 * @param key
 * @param iv
 * @returns {function(*=)}
 */
function factoryDecryption(key, config) {
	const {algorithm, serialNumber, iv} = config;
	let _key = key || serialNumber;
	const password = getPassword(_key);
	let decryption = (data) => {
		let decipher = crypto.createDecipheriv(algorithm, password, iv);
		let _1 = decipher.update(data);
		let _2 = decipher.final();
		return Buffer.concat([_1, _2], _1.length + _2.length);
	};
	decryption.equalsKey = (__key) => _key === __key;
	return decryption;
}

function setKeyAndLength(buf, key) {
	let [_buf, _len] = titleBaoWen.warpTitle(buf, key);
	return Buffer.concat([_buf, buf,], buf.length + _len);
}

function mergeConfig(_config) {
	return Object.assign({
		clearEncoding: 'utf8',
		cipherEncoding: 'base64',
		iv: ''
	}, _config);
}

function initEncryption(aseEjb) {
	const passwordLength = [32, 16, 32][parseInt(Math.random() * 10) % 3];
	let _encryption = factoryEncryption(mergeConfig({
		passwordLength: passwordLength,
		serialNumber: getSerialNumber(passwordLength),
		algorithm: `aes-${passwordLength * 8}-ecb`,
	}));
	if (aseEjb.si) clearTimeout(aseEjb.si);
	aseEjb.si = setTimeout(() => initEncryption(aseEjb), KEY_RESET /** 60 */ * 1000);
	aseEjb.encryption = undefined;
	aseEjb.encryption = _encryption;
}

function initDecryption(aseEjb) {
	const _ = (function factoryMergePackage() {
		let _package = Buffer.alloc(0);
		return (buf) => {
			buf = Buffer.concat([_package, buf], buf.length + _package.length);
			let {packageLength, keyLength, key, data, titleBaoWenLength} = titleBaoWen.decomTitle(buf);
			let packageSize = packageLength + titleBaoWenLength;//包的大小
			if (packageSize > buf.length && (_package = buf)) return;
			packageSize = packageSize - _package.length;
			_package = Buffer.alloc(0);
			let _return = {
				length: keyLength,
				key: key,
				data: data,
				packageSize: packageSize
			};
			return _return;
		}
	})();

	function getKeyAndLength(buf) {
		let dataList = [], _bufObj, vernier = 0, bufLength = buf.length, count = 0;
		while (vernier < bufLength && (++count) < 10) {
			_bufObj = _(buf.slice(vernier));
			if (_bufObj) {
				vernier += _bufObj.packageSize;
				dataList.push(_bufObj);
			} else vernier = bufLength;
		}
		return dataList;
	}

	let _decryption;
	aseEjb.decryption = undefined;
	aseEjb.decryption = (buf) => {
		let packageList = getKeyAndLength(buf);
		let bufList = packageList.map((item) => {
			let {key, data, length} = item;
			if (!_decryption || (_decryption && !_decryption.equalsKey(key))) _decryption = factoryDecryption(key, mergeConfig({
				passwordLength: length,
				serialNumber: key,
				algorithm: `aes-${length * 8}-ecb`
			}));
			return _decryption(data);
		});
		return Buffer.concat(bufList);
	}
}


function initAseEjb() {
	const aseEjb = () => initAseEjb();
	initEncryption(aseEjb);
	initDecryption(aseEjb);
	return aseEjb;
}

module.exports = exports = initAseEjb();
