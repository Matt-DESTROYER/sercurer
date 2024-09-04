// constant to determine how many identical socket.remoteAddress values are allowed before it is assumed that the IP is a proxy server
const SAME_SOCKET_ADDRESS_LIMIT = 50;

// rate limit on a number of `requests` allowed per `milliseconds`
function ratelimit(requests, milliseconds, proxy = null) {
	// bucket of IPs and logs of when each made a request
	const bucket = new Map();

	// variables to help prevent innacurate IP logging if a proxy is used
	let useSocketRemoteAddress = true,
		socketRemoteAddress = null,
		sameRemoteAddresses = 0;

	return function (req, res, next) {
		let ip = null;
		// if using socket.remoteAddress
		if (!proxy && useSocketRemoteAddress) {
			// if we haven't been explicitly been told there's no proxy
			if (proxy === null) {
				// if the address is the same
				if (req.socket.removeAddress === socketRemoteAddress) {
					sameRemoteAddresses++;
				} else {
					sameRemoteAddresses = 0;
					socketRemoteAddress = req.socket.removeAddress;
				}
				// if the same address is used more than SAME_SOCKET_ADDRESS_LIMIT times stop using socket.removeAddress and assume it is the IP of a proxy server
				if (sameRemoteAddresses > SAME_SOCKET_ADDRESS_LIMIT) {
					useSocketRemoteAddress = false;
				}
			}

			// set req.ip to the socket.remoteAddress
			ip = req.socket.remoteAddress;
		} else {
			// grab the x-forwarded-for header from the proxy server
			const x_forwarded_for = req.headers["x-forwarded-for"] || "";
			const comma = x_forwarded_for.indexOf(",");
			ip = (comma < 0) ? x_forwarded_for : x_forwarded_for.substring(0, comma);
		}

		req.ip = ip;

		// (prevent repeated use of Date.now())
		const currentTime = Date.now();
		// if the IP has been recorded
		const bucketed_ip = bucket.get(req.ip);
		if (bucketed_ip) {
			// remove any logs of requests past the specified duration
			for (let i = 0; i < bucketed_ip.length; i++) {
				if (currentTime - bucketed_ip[i] > milliseconds) {
					bucketed_ip.splice(i, 1);
					i--;
				}
			}
			// ratelimit based on whether or not the requests exceed the specified number
			if (bucketed_ip.length < requests) {
				bucketed_ip.push(currentTime);
			} else {
				// ratelimit and stop the request from continuing
				res.send("Ratelimited.");
				res.end();
				return;
			}
		} else {
			bucket.set(req.ip, [currentTime]);
		}
		// allow the request to continue
		next();
	};
}

// apply a number security headers based on a level of `security`
function headers(security = "high") {
	// load the options
	const options = {
		high: {
			"Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
			"Content-Security-Policy": "default-src 'self'; base-uri 'self'; form-action 'self'; img-src 'self'; object-src 'none'; frame-ancestors 'self'; require-trusted-types-for 'script'",
			"X-Frame-Options": "DENY",
			"X-Content-Type-Options": "nosniff",
			"Referrer-Policy": "strict-origin-when-cross-origin",
			"Permissions-Policy": "geolocation=(), midi=(), sync-xhr=(), accelerometer=(), gyroscope=(), magnetometer=(), camera=(), fullscreen=(self)",
			"Cross-Origin-Embedder-Policy": "require-corp",
			"Cross-Origin-Embedder-Policy-Report-Only": "require-corp",
			"Cross-Origin-Opener-Policy": "same-origin",
			"Cross-Origin-Opener-Policy-Report-Only": "same-origin",
			"Cross-Origin-Resource-Policy": "same-site"
		},
		medium: {
			"Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
			"Content-Security-Policy": "default-src 'self'; base-uri 'self'; form-action 'self'; img-src 'self'; frame-ancestors 'self'; require-trusted-types-for 'script'",
			"X-Frame-Options": "SAMEORIGIN",
			"X-Xss-Protection": "1; mode=block",
			"X-Content-Type-Options": "nosniff",
			"Referrer-Policy": "no-referrer-when-downgrade",
			"Permissions-Policy": "geolocation=(), midi=(), sync-xhr=(), accelerometer=(), gyroscope=(), magnetometer=(), camera=(), fullscreen=(self)",
			"Cross-Origin-Embedder-Policy": "require-corp",
			"Cross-Origin-Embedder-Policy-Report-Only": "require-corp",
			"Cross-Origin-Opener-Policy": "same-origin-allow-popups",
			"Cross-Origin-Opener-Policy-Report-Only": "same-origin-allow-popups",
			"Cross-Origin-Resource-Policy": "same-site"
		},
		low: {
			"Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
			"Content-Security-Policy": "default-src 'https:'",
			"Referrer-Policy": "no-referrer-when-downgrade"
		}
	};

	options.h = options.high;
	options.m = options.medium;
	options.l = options.low;
	options.none = options.n = {};

	security = security.toLowerCase();
	if (!options.hasOwnProperty(security)) {
		throw new Error("Invalid security level: '" + security + "', expected 'high', 'medium', or 'low'.");
	}

	// preload the requested set of options
	const headers = options[security];

	// apply the headers
	return function (req, res, next) {
		res.removeHeader("Strict-Transport-Security");
		res.removeHeader("X-Powered-By");
		res.set(headers);
		next();
	};
}

module.exports = {
	ratelimit,
	headers
};
