const net = require('net');
function factoryMiddleware(action) {
	let middlewareCatch = [];
	let middlewareVernier = {};
	let vernier = 0;
	action = action || [];

	function register(key, fn) {
		if (!middlewareVernier.hasOwnProperty(key)) {
			middlewareVernier[key] = [];
		}
		middlewareVernier[key].push(middlewareCatch.length);
		middlewareCatch.push(fn);
	}

	/**
	 * 重制状态
	 */
	function reset() {
		vernier = 0;
	}

	/**
	 * 设置action游标
	 * @param value
	 */
	function setVernier(value) {
		vernier = value;
	}

	function replaceRegister(key, fn) {
		if (middlewareVernier.hasOwnProperty(key)) {
			middlewareVernier[key].map(key => middlewareCatch[key] = undefined);
			middlewareVernier[key] = [];
		}
		register(key, fn);
	}

	/**
	 * 执行注册等队列
	 * @param middleware
	 * @param data
	 */
	function executeNext(middleware, data) {
		function factoryNext(_vernier) {
			let _action_vernier = vernier;
			reset();
			return (_data, _action) => {
				let fn = middleware[_vernier];
				_data = _data || data;
				if (_action && action.indexOf(_action) != -1) {
					setVernier(action.indexOf(_action));
					return jumpAction(_action, _data);
				}
				setVernier(_action_vernier);
				if (typeof fn !== 'undefined') fn = middlewareCatch[fn];
				if (fn) return fn(_data, factoryNext(_vernier + 1));
				execute(_data);
			}
		}

		if (middleware && middleware.length > 0) return factoryNext(0);
	}

	/**
	 * 跳转到指定action
	 * @param _action
	 * @param data
	 */
	function jumpAction(_action, data) {
		let next;
		if (_action) {
			next = executeNext(middlewareVernier[_action], data);
			if (next) next();
			else execute(data);
		}
		else vernier = 0;
	}

	/**
	 * 数据入口
	 * @param data
	 */
	function execute(data) {
		jumpAction(action[vernier++], data);
	}

	execute.register = register;
	execute.replaceRegister = replaceRegister;
	return execute;
}

function getHttpLine() {
	let _buffer = Buffer.alloc(0);

	function isHeaderTitleEnd() {
		for (var i = 0, len = _buffer.length - 3; i < len; i++) {
			if (_buffer[i] == 0x0d && _buffer[i + 1] == 0x0a && _buffer[i + 2] == 0x0d && _buffer[i + 3] == 0x0a) {
				return i + 4;
			}
		}
		return -1;
	}

	function getLine(headMsg) {
		const _msg = headMsg.toString();
		const httpHeaderList = _msg.replace('Proxy-Connection', 'Connection').split('\r\n');
		const method = httpHeaderList[0].split(' ')[0];
		let _httpLine;
		_httpLine = new RegExp(
			`([A-Z]+)\\s+${method === 'CONNECT' ? '' : 'http:\\/\\/'}([^:|^\\/]+):*([^\\/^\\s]*)([^\\?]*)(\\?*[^\\s]*)\\s*(HTTP\\/\\d+.\\d+)`
		);
		_httpLine = httpHeaderList[0].match(_httpLine);
		console.log(_msg);
		if (_httpLine) httpHeaderList[0] = `${_httpLine[1]} ${_httpLine[4]}${_httpLine[5]} ${_httpLine[6]}`.replace(/\s{2,}/g, ' ');
		else _httpLine = [
			httpHeaderList[0],
			httpHeaderList[0].split(' ')[0],
			_msg.replace(/[\s\S]*Host: ([^\r]+)\r\n[\s|\S]*/,'$1')
		];
		return {
			httpHead: httpHeaderList.join('\r\n'),
			headline: _httpLine,
		};
	}

	return function (msg) {
		let index;
		_buffer = Buffer.concat([_buffer, msg], _buffer.length + msg.length);
		if ((index = isHeaderTitleEnd()) < 0) return;
		let body = _buffer.slice(index, _buffer.length);
		let headMsgObj = getLine(_buffer.slice(0, index));
		let headBuffer = Buffer.from(headMsgObj.httpHead);
		return Object.assign(headMsgObj, {
			buf: Buffer.concat([headBuffer, body], headBuffer.length + body.length),
			body: body
		});
	}
}

/**
 * 创建tcp连接
 * @param port
 * @param address
 * @returns {*}
 */
function createProxyServer(port, address) {
	return net.createConnection(port, address);
}

/**
 * 判断是否包含请求头
 * @param msg
 * @returns {boolean}
 */
function isHttpHead(msg) {
	let method = msg.slice(0, 7).toString();
	return ['GET', 'POST', 'CONNECT'].indexOf(method.split(' ')[0]) != -1;
}

function packageManage() {
	function mergePackage(packageList) {
		return packageList.map(_ => addPackageSizeTitle(_))
	}

	function splitMergePackage(data) {
		let len, _buf = data, list = [];
		while (_buf.length > 0) {
			len = parseInt(_buf.slice(0, 5).toString());
			list.push(_buf.slice(5, 5 + len));
			_buf = _buf.slice(5 + len);
		}
		return list;
	}

	function addPackageSizeTitle(buf) {
		let len = Buffer.alloc(5), b_len = buf.length;
		len.write(b_len.toString());
		return Buffer.concat([len, buf], 5 + b_len);
	}

	function writeBuf(length) {
		if (!Array.isArray(length)) length = [length];
		length = length.reduce((a, b) => a + b);
		let buf = Buffer.alloc(length);
		let offset = 0;
		let fn = (str, len) => {
			buf.write(str.toString().slice(-len), offset, len);
			offset += len || 0;
			return fn;
		};
		fn._len = length;
		fn.buf = buf;
		return fn;
	}

	function bufSlice(buf) {
		let offset = 0;
		return (len) => buf.slice(offset, offset = offset + len);
	}

	return {
		mergePackage,
		writeBuf,
		bufSlice,
		splitMergePackage,
		addPackageSizeTitle
	}
}


module.exports = {
	getHttpLine,
	createProxyServer,
	isHttpHead,
	packageManage: packageManage(),
	factoryMiddleware
};