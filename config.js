module.exports = exports = {
	CN_ADDRESS:'127.0.0.1',
	CN_PORT: process.env.cn_port || 6789,
	EN_ADDRESS:'127.0.0.1',
	EN_PORT: process.env.en_port || 6788,
	PAC_PORT: process.env.en_port || 6787,

	UDP_EN_ADDRESS:'127.0.0.1',
	UDP_EN_PORT:6788,
	UDP_CN_ADDRESS:'127.0.0.1',
	UDP_CN_PORT:6789,

	KEY_RESET:10,

	splitPackageSize: 9000,
	packageMaxDisparity: 1,

	countBufLen:8,
	hashBufLen:13,
	eventBufLen:15,
	packageSize:12,
	splitBufPackageSize:4,
};