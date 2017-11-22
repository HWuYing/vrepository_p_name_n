const dns = require('dns');
dns.setServers([
	'114.114.114.114',
	'1.2.4.8'
]);
module.exports = exports = function (address,IPV6) {
	return new Promise((resolve, reject) => {
		let resolveDns;
		if (/\d+\.\d+\.\d+\.\d+/.test(address) || address == 'localhost') return resolve([address]);
		if(!IPV6) resolveDns = dns.resolve4.bind(dns);
		else resolveDns = dns.resolve6.bind(dns);
		resolveDns(address, (err, addresses) => {
			if (err) return reject(err);
			resolve(addresses);
			// resolve(['127.0.0.1']);
		});
	})
};