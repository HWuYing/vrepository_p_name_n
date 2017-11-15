const { factoryMiddleware} = require('./../utils');
const tcpClient = require('./tcp_client');

const net = require('net');

function serverMiddleware(server) {
	function adapter(){}
	adapter.error = factoryMiddleware(['before', 'error', 'after']);
	adapter.close = factoryMiddleware(['before', 'close', 'after']);
	adapter.connection = factoryMiddleware(['before', 'connection', 'after']);

	server.on('connection', adapter.connection);
	server.on('error', adapter.error);
	server.on('close', adapter.close);
	return adapter;
}


module.exports = exports = function (port) {
	let server = net.createServer();
	let _serverMiddleware = serverMiddleware(server);

	_serverMiddleware.connection.register('before',(client, next) => {
		next(tcpClient(client));
	});

	server.listen(port, function () {
		const address = server.address();
		console.log(`TCP服务器监听 ${address.address}:${address.port}`);
	});

	return _serverMiddleware;
};