const {factoryMiddleware} = require('./utils');

let onConnect = (_proxySocketMiddleware, proxySocket) => (httpHeaderObj, next) => {
	if (httpHeaderObj.headline[1] === 'CONNECT') {
		_proxySocketMiddleware.data("HTTP/1.1 200 Connection Established\r\nConnection: close\r\n\r\n")
	} else {
		proxySocket.write(httpHeaderObj.buf);
	}
	next();
};

let onData = (socket) => (msg, next) => {
	if (!Array.isArray(msg)) msg = [msg];
	if (socket.writable) msg.map((_msg) => socket.write(_msg));
	else socket.destroy();
	next();
};

let onEnd = (socket) => (msg, next) => {
	socket.end(msg);
	next();
};

let onError = (socket, proxySocket) => (e, next) => {
	console.log(e.message);
	socket.destroy();
	proxySocket.destroy();
	next();
};

let writeBuf = (socket, proxySocket) => (buf, next) => {
	if (!Array.isArray(buf)) buf = [buf];
	buf.map((_buf) => proxySocket.write(_buf));
	next();
};

function proxySocketMiddleware(proxySocket) {
	function adapter(httpHeaderObj) {
		proxySocket.on('connect', () => adapter.connect(httpHeaderObj));
		return adapter.write;
	}

	adapter.connect = factoryMiddleware(['before', 'connect', 'after']);
	adapter.write = factoryMiddleware(['before', 'write', 'after']);
	adapter.error = factoryMiddleware(['before', 'error', 'after']);
	adapter.data = factoryMiddleware(['before', 'data', 'after']);
	adapter.end = factoryMiddleware(['before', 'end', 'after']);


	proxySocket.on('data', (msg => adapter.data(msg)));
	proxySocket.on('end', (message) => adapter.end(message));
	proxySocket.on('error', adapter.error);

	return adapter;
}

module.exports = exports = function (socket, proxySocket) {

	let _proxySocketMiddleware = proxySocketMiddleware(proxySocket);
	_proxySocketMiddleware.connect.register('connect', onConnect(_proxySocketMiddleware, proxySocket));
	_proxySocketMiddleware.write.register('write', writeBuf(socket, proxySocket));
	_proxySocketMiddleware.data.register('data', onData(socket));
	_proxySocketMiddleware.error.register('error', onError(socket, proxySocket));
	_proxySocketMiddleware.end.register('end', onEnd(socket));

	socket.on('error', (e) => {
		console.log(e.message);
		socket.destroy();
		proxySocket.destroy();
	});
	return _proxySocketMiddleware;
};