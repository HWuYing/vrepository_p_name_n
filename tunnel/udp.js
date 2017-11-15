const { factoryMiddleware } = require('../utils');
const dgram = require('dgram');

function socketMiddleware(socket) {
	let adapter = (msg) => adapter.send(msg);

	adapter.send = factoryMiddleware(['before', 'send', 'after']);
	adapter.close = factoryMiddleware(['before', 'close', 'after']);
	adapter.error = factoryMiddleware(['before', 'error', 'after']);
	adapter.message = factoryMiddleware(['before', 'message', 'after']);

	socket.on('message', (msg, info) => adapter.message({msg, info}));
	socket.on('error', adapter.error);
	socket.on('close', adapter.close);

	return adapter;
}


module.exports = exports = function (port) {
	const udp_socket = dgram.createSocket('udp4');
	const _socketMiddleware = socketMiddleware(udp_socket);
	udp_socket.on('listening', () => {
		const address = udp_socket.address();
		console.log(`UDP服务器监听 ${address.address}:${address.port}`);
	});

	_socketMiddleware.send.register('send' , (_, next) =>{
		let {msg, port, address} = _;
		udp_socket.send(msg[0], port, address, _socketMiddleware.error);
		next();
	});

	udp_socket.bind(port);

	return _socketMiddleware;
};