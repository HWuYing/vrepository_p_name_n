const {CN_PORT, EN_PORT, EN_ADDRESS, UDP_CN_PORT, UDP_EN_ADDRESS, UDP_EN_PORT} = require('../config');
const aseEjb = require('./../aes_ejb')();
const {isHttpHead, getHttpLine} = require('./../utils');

const factoryTcpServer = require('./../tunnel/tcp_server');
const factoryTcpClient = require('./../tunnel/tcp_client');
const factoryUdp = require('./../tunnel/udp');
const udpUtil = require('./../tunnel/udp_util');

const packageMap = udpUtil();

let serverMiddleware = factoryTcpServer(CN_PORT);

let udpServer = udpAdapter(factoryUdp(UDP_CN_PORT));


serverMiddleware.connection.register('connection', (socket, next) => {
	next(socketAdapter(socket));
});

function udpAdapter(udp) {
	udp.send.register('before', (_, next) => {
		next({
			msg: aseEjb.encryption(_),
			port: UDP_EN_PORT,
			address: UDP_EN_ADDRESS
		})
	});

	udp.message.register('message', (_) => {
		let {hash, count, data} = packageMap.decomPackage(aseEjb.decryption(_.msg));
		// console.log(`============udpMessage ${hash} ${count}===================`);
		// console.log(data.length);
		packageMap.write(hash, count, data);
	});
	return udp;
}

let vernier = 0;

let clientMiddleware = clientAdapter(factoryTcpClient(EN_PORT, EN_ADDRESS));

function socketAdapter(socket) {
	const hash = (new Date().getTime() + (++vernier)).toString();
	packageMap.add(hash, socket);
	let count = 0;
	// console.log(`===================socket ${hash}=================`);
	socket.data.register('data', (_) => {
		let httpObj, sendObj;
		// console.log(`=========client ${hash} require==========`);
		// if (isHttpHead(_)) console.log(_.toString());
		// else console.log(_.length);
		if (count == 0 && isHttpHead(_)) {
			httpObj = getHttpLine()(_);
			clientMiddleware({
				data: packageMap.warpPackage(
					hash, count,
					Buffer.from(`${httpObj.headline[2]}:${httpObj.headline[3] || 80}`)
				), event: 'createConnect'
			});
			count += packageMap.createFirstWritUdp(hash, _, udpServer);
		} else {
			sendObj = {hash, count, data: _};
			clientMiddleware.writeUdp(sendObj);
			count = sendObj.count;
		}
	});


	socket.end.register('end', () => {
		// console.log(`===============client ${hash} end==============`);
		// console.log(count);
		clientMiddleware({data: packageMap.warpPackage(hash, count), event: 'end'});
		packageMap.end(hash, count);
	});

	socket.error.register('error', (e) => {
		console.log(`====================client ${count} error===============`);
		console.log(hash);
		console.log(e.message);
		clientMiddleware({data: packageMap.warpPackage(hash, count), event: 'error'});
		packageMap.end(hash, count);
	});

}

function clientAdapter(client) {
	let connectStatus = false;

	client.connect.register('connect', () => connectStatus = true);

	client.write.register('before', (_, next) => {
		next(aseEjb.encryption(packageMap.warpEventPackage(_.event, _.data)));
	});

	client.writeUdp.register('before', (_, next) => {
		let {data, hash, count} = _;
		// console.log(`===========data ${hash} ${count}=================`);
		// console.log(data.length);
		// console.log(count);
		packageMap.splitPackage(data, (__) => next({
			count: _.count,
			hash: hash,
			buf: packageMap.warpPackage(hash, _.count++, __),
		}));
	});
	client.writeUdp.register('writeUdp', (_) => {
		// console.log(`===========data ${_.hash} ${_.count}=================`);
		// console.log(_.buf.length);
		udpServer(_.buf)
	});

	client.data.register('before', (_, next) => {
		packageMap.decomEventPackage(aseEjb.decryption(_), next);
	});

	client.data.register('data', (_) => {
		let {event, hash, data} = _;
		if (event.indexOf('end') != -1) packageMap.end(hash, parseInt(data.toString()));
		else if (event.indexOf('connect') != -1) packageMap.firstWriteUdp(hash);
		else if (event.indexOf('error') != -1) packageMap.error(hash, data);
	});

	return client;
}