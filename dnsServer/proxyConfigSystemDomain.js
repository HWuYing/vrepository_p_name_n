const domainProxy = {
	'*.baidu.com': '172.16.10.126',
	'*.bdstatic.com': '172.16.10.126',
	'*.google.com': '172.16.10.126',
	'*.github.com': '172.16.10.126',
	'github.com': '172.16.10.126',
};
module.exports = exports = function (domain) {
	if (domain == 'localhost' || /^\d{3}\.\d{3}\.\d{3}\.\d{3}$/.test(domain)) return domain;
	if (domainProxy.hasOwnProperty(domain)) return domainProxy[domain];
	let parts = domain.split('.');
	let key;
	while (parts.length) {
		parts[0] = '*';
		key = parts.join('.');
		parts.shift();
		if (domainProxy.hasOwnProperty(key)) return domainProxy[key];
	}
	return false;
};