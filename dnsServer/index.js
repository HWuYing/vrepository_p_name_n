const factoryUdp = require('./../tunnel/udp');
const factoryTcp = require('./../tunnel/tcp_server');
const parseFromBuffer = require('./parseFromBuffer');

const structure = {
	HEADER: {
		//标识字段
		//客户端会解析服务器返回的DNS应答报文
		//获取ID值与请求报文设置的ID值做比较，
		//如果相同，则认为是同一个DNS会话
		ID: {name: 'ID', byt_offset: 0, byt_length: 2},
		//标志字段
		FLAGS: {
			name: 'FLAGS', byt_length: 2,
			body: [
				//QR: 0表示查询报文，1表示响应报文 , 1bit;
				{name: 'QR', bit_length: 1},
				//opcode: 通常值为0（标准查询），其他值为1（反向查询）和2（服务器状态请求）,
				//[3,15]保留值, 4bit
				{name: 'OPCODE', bit_length: 4},
				//AA: 表示授权回答（authoritative answer）– 这个比特位在应答的时候才有意义，
				//指出给出应答的服务器是查询域名的授权解析服务器; 1bit
				{name: 'AA', bit_length: 1},
				//TC: 表示可截断的（truncated）–用来指出报文比允许的长度还要长，导致被截断; 1bit
				{name: 'TC', bit_length: 1},
				//RD: 表示期望递归(Recursion Desired) – 这个比特位被请求设置，应答的时候使用的相同的值返回。
				//如果设置了RD，就建议域名服务器进行递归解析，递归查询的支持是可选的; 1bit
				{name: 'RD', bit_length: 1},
				//RA: 表示支持递归(Recursion Available) – 这个比特位在应答中设置或取消，
				//用来代表服务器是否支持递归查询; 1bit
				{name: 'RA', bit_length: 1},
				//Z : 保留值，暂未使用; 3bit
				{name: 'Z', bit_length: 3},
				//RCODE：该字段占4位，该字段仅在DNS应答时才设置。用以指明是否发生了错误。
				//允许取值范围及意义如下：
				//0：无错误情况，DNS应答表现为无错误。
				//1：格式错误，DNS服务器不能解释应答。
				//2：严重失败，因为名字服务器上发生了一个错误，DNS服务器不能处理查询。
				//3：名字错误，如果DNS应答来自于授权的域名服务器，意味着DNS请求中提到的名字不存在。
				//4：没有实现。DNS服务器不支持这种DNS请求报文。
				//5：拒绝，由于安全或策略上的设置问题，DNS名字服务器拒绝处理请求。
				//6 ～15 ：留为后用。
				{name: 'RCODE', bit_length: 4},
			]
		},
		//QDCOUNT: 无符号16bit整数表示报文请求段中的问题记录数
		QDCOUNT: {name: 'QDCOUNT', byt_length: 2},

		//ANCOUNT: 无符号16bit整数表示报文回答段中的回答记录数
		ANCOUNT: {name: 'ANCOUNT', byt_length: 2},

		//NSCOUNT: 无符号16bit整数表示报文授权段中的授权记录数。
		NSCOUNT: {name: 'NSCOUNT', byt_length: 2},

		//ARCOUNT: 无符号16bit整数表示报文附加段中的附加记录数。
		ARCOUNT: {name: 'ARCOUNT', byt_length: 2},
	},
	QUESTION: {

		//QNAME 无符号8bit为单位长度不限表示查询名(广泛的说就是：域名).
		QNAME: {name: 'QNAME', byt_length: 1},

		//QTYPE无符号16bit整数表示查询的协议类型
		QTYPE: {name: 'QTYPE', byt_length: 2},

		//QCLASS 无符号16bit整数表示查询的类,比如，IN代表Internet.
		QCLASS: {name: 'QCLASS', byt_length: 2}
	}
};


function readAnswerPackage(buf, offset) { //{{{
	var ttl, len, rdata;

	ttl = buf.readUInt32BE(offset);
	offset += 4;
	len = buf.readUInt16BE(offset);
	offset += 2;
	rdata = buf.toString('base64', offset, offset + len);
	offset += len;
	return {
		data: {
			ttl: ttl,
			rdata: rdata
		},
		next: offset
	};
}

function factoryReadPackage(buf, callback) {
	function readDomainName(offset) {
		var length, ret = [],
			next = false;

		while ((length = buf.readUInt8(offset++)) > 0) {
			if ((length & 0xC0) == 0xC0) {
				if (next === false) {
					next = offset + 1;
				}
				offset = ((length & (~0xC0)) << 8) | buf.readUInt8(offset);
				continue;
			}
			ret.push(buf.toString('ascii', offset, offset + length));
			offset += length;
		}
		return {
			name: ret.join("."),
			next: (next === false ? offset : next)
		};
	}

	return (offset, count) => {
		let info, _info, data = [], type, klass;
		while (count--) {
			info = readDomainName(offset);
			offset = info.next;

			type = buf.readUInt16BE(offset);
			offset += 2;

			klass = buf.readUInt16BE(offset);
			offset += 2;
			info = {
				name:info.name,
				type:type,
				klass:klass
			};
			if (callback && typeof callback == 'function') {
				_info = callback(buf, offset);
				info = Object.assign(info, _info.data);
				offset = _info.next;
			}
			data.push(info);
		}
		return {
			data: data,
			next: offset
		}
	}
}


function _parseFromBuffer(buf) {
	const query = {};
	const header = query.header = {};
	const body = query.body = {};
	let qdcount, ancount, nscount, arcount;
	let offset, info;
	header.id = buf.readUInt16BE(0);
	header.flags = buf.readUInt16BE(2);
	header.qr = ((0x08 << 12) & header.flags) >> 12;
	header.opcode = ((0x0f << 11) & header.flags) >> 11;
	header.aa = ((0x01 << 10) & header.flags) >> 10;
	header.tc = ((0x01 << 9) & header.flags) >> 9;
	header.rd = ((0x01 << 8) & header.flags) >> 8;
	header.ra = ((0x01 << 7) & header.flags) >> 7;
	header.rcode = 0x0f & header.flags;

	qdcount = buf.readUInt16BE(4);
	ancount = buf.readUInt16BE(6);
	nscount = buf.readUInt16BE(8);
	arcount = buf.readUInt16BE(10);

	offset = 12;

	info = factoryReadPackage(buf)(offset, qdcount);
	body.queries = info.data;
	offset = info.next;

	info = factoryReadPackage(buf,readAnswerPackage)(offset, ancount);
	body.answers = info.data;
	offset = info.next;

	info = factoryReadPackage(buf,readAnswerPackage)(offset, nscount);
	body.authoritativeNameservers = info.data;
	offset = info.next;

	info = factoryReadPackage(buf,readAnswerPackage)(offset, arcount);
	body.additionalRecords = info.data;
	return query;
}

function onData(_, next) {
	next(_.msg);
}

module.exports = exports = function () {
	function udpAdapter(udp) {
		udp.send.register('before', (_, next) => {
			console.log(_);
		});
		udp.message.register('before', onData)
		udp.message.register('message', (_) => {
			let q = _parseFromBuffer(_);
			console.log(q);
		});
		return udp;
	}

	return udpAdapter(factoryUdp(53));
};