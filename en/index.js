const {EN_PORT, countBufLen, UDP_CN_PORT, UDP_CN_ADDRESS, UDP_EN_PORT} = require('../config');
const parsetDns = require('./../dns');
const {getHttpLine, isHttpHead} = require('./../utils');
const aseEjb = require('./../aes_ejb')();

const factoryTcpServer = require('./../tunnel/tcp_server');
const factoryTcpClient = require('./../tunnel/tcp_client');
const factoryUdp = require('./../tunnel/udp');
const udpUtil = require('./../tunnel/udp_util');


const clientMap = udpUtil();

let udpServer = udpAdapter(factoryUdp(UDP_EN_PORT));

/**
 * tcp服务器
 * @param socket
 */
let serverMiddleware = factoryTcpServer(EN_PORT);
serverMiddleware.connection.register('connection', (socket, next) => {
	next(socketAdapter(socket));
});

function udpAdapter(udp) {
	udp.send.register('before', (_, next) => next({
		msg: aseEjb.encryption(_),
		port: UDP_CN_PORT,
		address: UDP_CN_ADDRESS
	}));

	udp.message.register('message', (_) => {
		let {hash, count, data} = clientMap.decomPackage(aseEjb.decryption(_.msg));
		// console.log(`============udpMessage ${hash} ${count}===================`);
		// console.log(data.length);
		clientMap.write(hash, count, data);
	});

	return udp;
}

function socketAdapter(socket) {
	socket.data.register('before', (_, next) => {
		clientMap.decomEventPackage(aseEjb.decryption(_), next);
	});
	socket.data.register('data', (_, next) => {
		let event = _.event;
		if (event.indexOf('end') != -1) next(_, 'end');
		else if (event.indexOf('createConnect') != -1) next(_, 'createConnect');
		else if (event.indexOf('error') != -1) next(_, 'error');
	});

	socket.data.register('end', (_) => {
		// console.log(`===============client end==============`);
		clientMap.end(_.hash);
	});

	socket.data.register('error', (_) => {
		clientMap.error(_.hash);
	});

	socket.data.register('createConnect', (_) => {
		let ym = _.data.toString().split(":");
		parsetDns(ym[0]).then(addresses => {
			let clientMiddleware = factoryTcpClient(ym[1], addresses[0]);
			// let clientMiddleware = factoryTcpClient(49583, '127.0.0.1');
			clientAdapter(clientMiddleware, socket, {
				headline: _.data.toString(),
				hash: _.hash
			});
		}).catch(e => {
			console.log(e);
			console.log(ym[0]);
			socket.write(clientMap.warpEventPackage('error', _.hash, _.count));
		});
	});

	socket.write.register('before', (_, next) => next(aseEjb.encryption(_)));
}

/**
 * tcp客户端连接
 * @param client
 * @param socket
 */
function clientAdapter(client, socket, msg) {
	let dataCount = 0;
	client.write.register('before', (_, next) => {
		let httpObj;
		if (isHttpHead(_)) {
			httpObj = getHttpLine()(_);
			if (httpObj.headline[1] === 'CONNECT') {
				client.data(Buffer.from("HTTP/1.1 200 Connection Established\r\nConnection: close\r\n\r\n"));
			} else {
				next(httpObj.buf);
			}
		}
		else next(_);
	});

	client.data.register('before', (_, next) => {
		// console.log(`==============server ${msg.hash} send message=====================`);
		// console.log(_.length);
		clientMap.splitPackage(_, next);
	});

	client.data.register('data', (_) => {
		// console.log(`===========data ${msg.hash} ${dataCount}=================`);
		// console.log(_.length);
		udpServer(clientMap.warpPackage(msg.hash, dataCount++, _));
	});

	client.connect.register('connect', () => {
		// console.log(`=============server ${msg.hash} connect==================`);
		clientMap.add(msg.hash.toString(), client);
		socket.write(clientMap.warpEventPackage('connect', msg.hash, msg.count));
	});
	client.error.register('error', (e) => {
		console.log(`====================server ${dataCount} error===============`);
		console.log(msg.hash);
		console.log(e.message);
		clientMap.error(msg.hash.toString());
		socket.write(clientMap.warpEventPackage('error', msg.hash, msg.count));
	});
	client.end.register('end', (_msg) => {
		// console.log(`===============server ${msg.hash} end==============`);
		// console.log(dataCount);
		clientMap.end(msg.hash.toString(), dataCount);
		client.ended = true;
		let _datacount = Buffer.alloc(countBufLen, '');
		_datacount.write(dataCount.toString().slice(-countBufLen));
		socket.write(clientMap.warpEventPackage('end', msg.hash, dataCount,
			_datacount));
	})

}