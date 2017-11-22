const {CN_PORT, EN_PORT, EN_ADDRESS, UDP_CN_PORT, UDP_EN_ADDRESS, UDP_EN_PORT} = require('../config');
const createAseEjb = require('./../aes_ejb');
const {isHttpHead, getHttpLine} = require('./../utils');

const factoryDnsServer = require('./../dnsServer');
const factoryTcpServer = require('./../tunnel/tcp_server');
const factoryTcpClient = require('./../tunnel/tcp_client');
const factoryUdp = require('./../tunnel/udp');
const UdpUtil = require('./../tunnel/udp_util');
const TcpUtil = require('./../tunnel/tcp_util');

const packageMap = new UdpUtil();
const aesEjbUdp = createAseEjb();
const aesEjbTcp = createAseEjb();

let dnsServer = factoryDnsServer();
let serverMiddleware = factoryTcpServer(CN_PORT);
let _serverMiddleware = factoryTcpServer(80);
let udpServer = udpAdapter(factoryUdp(UDP_CN_PORT));

serverMiddleware.connection.register('connection', (socket, next) => next(socketAdapter(socket, CN_PORT)));
_serverMiddleware.connection.register('connection', (socket, next) => next(socketAdapter(socket, 80)));

function udpAdapter(udp) {
	udp.send.register('before', (_, next) => {
		next({
			msg: aesEjbUdp.encryption(_),
			port: UDP_EN_PORT,
			address: UDP_EN_ADDRESS
		})
	});

	udp.message.register('message', (_) => {
		let {hash, count, data} = UdpUtil.decomPackage(aesEjbUdp.decryption(_.msg));
		// console.log(`============udpMessage ${hash} ${count}===================`);
		// console.log(data.length);
		packageMap.write(hash, count, data);
	});
	return udp;
}

let vernier = 0;

let clientMiddleware = clientAdapter(factoryTcpClient(EN_PORT, EN_ADDRESS));


function formatHttps(buf) {
	console.log('=======https format=======');
	console.log(buf);
	// let ProtocolVersion = buf.readUInt16BE(0);
	let contentType = buf.readUInt8(0);
	let version = buf.readUInt8(1)+'.'+buf.readUInt8(2);
	let packageLength = buf.readUInt16BE(3);
	let HandshakeType = buf.readUInt8(5);
	let messageLength = buf.slice(6,9).toString();
	let body = buf.slice(9);

	let maxVersion = body.readUInt8(0)+'.'+ body.readUInt8(1);
	let timstamp = buf.readUInt32BE(2);
	// let timstamp = buf.readUInt32BE(2);
	let Random = buf.slice(6,34);
	// buf.readUInt16BE(3),
	// let sessionCount = buf.readUInt8(34);
	console.log(contentType);
	console.log(version);
	console.log(packageLength);
	console.log(HandshakeType);
	console.log(messageLength);
	console.log(maxVersion);
	console.log(timstamp);
	console.log(Random);
	throw new Error('');
}



function socketAdapter(socket, port) {
	const hash = (new Date().getTime() + (++vernier)).toString();
	packageMap.add(hash, socket);
	let count = 0;
	console.log(`===================socket ${hash}=================`);
	socket.data.register('data', (_) => {
		let httpObj, sendObj, ym, _port,str;
		console.log(`=========client ${hash} ${port} require==========`);
		if (isHttpHead(_)) console.log(_.toString());
		else console.log(_.length);
		if (count == 0 && (port === 443 || isHttpHead(_))) {
			if(port == 443){
				str = '';
				formatHttps(_);
				for (let i = 0; i < _.length; i++) {
					// console.log(_[i]);
					str += String.fromCharCode(_[i]);
				}
				console.log(str);
				// ym = str.replace()
			}else{
				httpObj = getHttpLine()(_);
				ym = httpObj.headline[2];
			}
			clientMiddleware({
				data: UdpUtil.warpPackage(
					hash, count,
					Buffer.from(`${ym}:${_port}`)
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
		clientMiddleware({data: UdpUtil.warpPackage(hash, count), event: 'end'});
		packageMap.end(hash, count);
	});

	socket.error.register('error', (e) => {
		console.log(`====================client ${count} error===============`);
		console.log(hash);
		console.log(e.message);
		clientMiddleware({data: UdpUtil.warpPackage(hash, count), event: 'error'});
		packageMap.end(hash, count);
	});

}

function clientAdapter(client) {
	let connectStatus = false;

	client.connect.register('connect', () => connectStatus = true);

	client.write.register('before', (_, next) => {
		next(aesEjbTcp.encryption(TcpUtil.warpEventPackage(_.event, _.data)));
	});

	client.writeUdp.register('before', (_, next) => {
		let {data, hash, count} = _;
		// console.log(`===========data ${hash} ${count}=================`);
		// console.log(data.length);
		UdpUtil.splitPackage(data, (__) => next({
			count: _.count,
			hash: hash,
			buf: UdpUtil.warpPackage(hash, _.count++, __),
		}));
	});
	client.writeUdp.register('writeUdp', (_) => {
		// console.log(`===========data ${_.hash} ${_.count}=================`);
		// console.log(_.buf.length);
		udpServer(_.buf)
	});

	client.data.register('before', (_, next) => {
		TcpUtil.decomEventPackage(aesEjbTcp.decryption(_), next);
	});

	client.data.register('data', (_) => {
		let {event, hash, data} = _;
		if (event.indexOf('end') != -1) packageMap.end(hash, parseInt(data.toString()));
		else if (event.indexOf('connect') != -1) packageMap.firstWriteUdp(hash);
		else if (event.indexOf('error') != -1) packageMap.error(hash, data);
	});

	return client;
}