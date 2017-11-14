const {factoryMiddleware, createProxyServer} = require('./../utils');

function proxySocketMiddleware(proxySocket) {
	function adapter(httpHeaderObj) {
		 adapter.write(httpHeaderObj);
	}
	adapter.connect = factoryMiddleware(['before', 'connect', 'after']);
	adapter.write = factoryMiddleware(['before', 'write', 'after']);
	adapter.error = factoryMiddleware(['before', 'error', 'after']);
	adapter.data = factoryMiddleware(['before', 'data', 'after', 'createConnect','end','error']);
	adapter.destroy = factoryMiddleware(['before', 'end', 'after']);
	adapter.end = factoryMiddleware(['before', 'end', 'after']);
	adapter.close = factoryMiddleware(['before', 'close', 'after']);
	adapter.writeUdp = factoryMiddleware(['before', 'writeUdp', 'after']);
	adapter.timeout = factoryMiddleware(['before', 'timeout', 'after']);

	proxySocket.on('data', (msg => adapter.data(msg)));
	proxySocket.on('end', (message) =>  adapter.end(message));
	proxySocket.on('error', adapter.error);
	proxySocket.on('close', adapter.close);
	proxySocket.on('connect', adapter.connect);
	proxySocket.on('timeout', adapter.timeout);
	return adapter;
}


let onConnect = (proxySocket,_proxySocketMiddleware) => (httpHeaderObj, next) => {
	next(httpHeaderObj);
};
let onError = (proxySocket,_proxySocketMiddleware) => (e, next) => {
	console.log(e.message);
	_proxySocketMiddleware.destroy();
	next(e);
};
let onEnd = (proxySocket,_proxySocketMiddleware) => (e, next) => {
	if(!_proxySocketMiddleware.ended) proxySocket.end();
	_proxySocketMiddleware.ended = true;
	proxySocket.destroy();
	_proxySocketMiddleware.destroyed = false;
	next(e);
};
let destroy = (proxySocket,_proxySocketMiddleware) => (_,next) => {
	_proxySocketMiddleware.end();
};
let writeBuf = (proxySocket) => (buf, next) => {
	if (!Array.isArray(buf)) buf = [buf];
	buf.map((_buf) => proxySocket.write(_buf));
	next(buf);
};

module.exports = exports = function (port, address) {
	let proxySocket = typeof port == 'object' ? port : createProxyServer(port, address);
	let _proxySocketMiddleware = proxySocketMiddleware(proxySocket);
	_proxySocketMiddleware.ended = false;
	_proxySocketMiddleware.destroyed = false;
	_proxySocketMiddleware.connect.register('connect', onConnect(proxySocket,_proxySocketMiddleware));
	_proxySocketMiddleware.error.register('error', onError(proxySocket,_proxySocketMiddleware));
	_proxySocketMiddleware.write.register('write', writeBuf(proxySocket));
	_proxySocketMiddleware.destroy.register('destroy',destroy(proxySocket,_proxySocketMiddleware));
	_proxySocketMiddleware.end.register('end',onEnd(proxySocket,_proxySocketMiddleware));
	return _proxySocketMiddleware;
};