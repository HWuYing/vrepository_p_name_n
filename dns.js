const dns = require('dns');

module.exports = exports = function (address) {
	return new Promise((resolve, reject) => {
		if(/\d+\.\d+\.\d+\.\d+/.test(address) || address == 'localhost') return resolve([address]);
		dns.resolve4(address, (err,addresses) =>{
			if(err) return reject(err);
			resolve(addresses);
		});
	})
};