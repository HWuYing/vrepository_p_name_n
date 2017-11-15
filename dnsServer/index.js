const factoryUdp = require('./../tunnel/udp');

let udpServer = udpAdapter(factoryUdp(53));

function udpAdapter(udp) {
	udp.send.register('before', (_, next) => {
		console.log(_);
	});

	udp.message.register('message', (_) => {
		console.log(_);
	});
	return udp;
}