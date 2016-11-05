// ²Î¿¼ git:Crypt.js apache:DigestUtils Md5Crypt.class
var Md5Crypt = function(){
	String.prototype.getBytes= function(){
		
		var ch, st, re = [];  
		  for (var i = 0; i < this.length; i++ ) {  
		    ch = this.charCodeAt(i);  // get char   
		    st = [];                 // set up "stack"  
		    do {  
		      st.push( ch & 0xFF );  // push byte to stack  
		      ch = ch >> 8;          // shift value down by 1 byte  
		    }    
		    while ( ch );  
		    // add stack contents to result  
		    // done because chars have "wrong" endianness  
		    re = re.concat( st.reverse() );  
		  }  
		  // return an array of bytes  
		  return re;  
	}
	
	
	// md5 add salt by zxy  = apache.md5Crypt
	function md5Crypt(keyStr, saltStr, prefix) {
		
		prfix = "$1$";
		
		var keyLen = keyStr.getBytes().length;
	
	    var ctx = new MD5();
	
	    /*
	     * The password first, since that is what is most unknown
	     */
	    ctx.update( keyStr.getBytes());
	
	    /*
	     * Then our magic string
	     */
	    ctx.update(prefix.getBytes());
	
	    /*
	     * Then the raw salt [52, 107, 103, 97, 57]
	     */
	    ctx.update(saltStr.getBytes());
		
	    /*
	     * Then just as many characters of the MD5(pw,salt,pw)
	     */
	    var ctx1 = new MD5();
	    ctx1.update(keyStr.getBytes());
	    ctx1.update(saltStr.getBytes());
	    ctx1.update(keyStr.getBytes());
	    
		var finalb = ctx1.digest();
	 
	    var ii = keyLen;
	    while (ii > 0) {
	        ctx._update(finalb, 0, ii > 16 ? 16 : ii);
	        ii -= 16;
	    }
	    finalb=[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
	    ii = keyLen;
	    var j = 0;
	    while (ii > 0) {
	        if ((ii & 1) == 1) {
	            ctx.update(finalb[j]);
	        } else {
	            ctx.update(keyStr.getBytes()[j]);
	        }
	        ii >>= 1;
	    }
	
	    /*
	     * Now make the output string
	     */
	    var passwd = new String(prefix + saltStr + "$");
	    finalb = ctx.digest();

	    /*
	     * and now, just to make sure things don't run too fast On a 60 Mhz Pentium this takes 34 msec, so you would
	     * need 30 seconds to build a 1000 entry dictionary...
	     */
	    for (var i = 0; i < 1000; i++) {
	        ctx1 = new MD5();
	        if ((i & 1) != 0) {
	            ctx1.update(keyStr.getBytes());
	        } else {
	            ctx1.update(finalb, 0, 16);
	        }
	
	        if (i % 3 != 0) {
	            ctx1.update(saltStr.getBytes());
	        }
	
	        if (i % 7 != 0) {
	            ctx1.update(keyStr.getBytes());
	        }
	
	        if ((i & 1) != 0) {
	            ctx1.update(finalb, 0, 16);
	        } else {
	            ctx1.update(keyStr.getBytes());
	        }
	        finalb = ctx1.digest();
	        	        
	    }
	    
	    passwd = b64from24bit(finalb[0], finalb[6], finalb[12], 4, passwd);
	    passwd = b64from24bit(finalb[1], finalb[7], finalb[13], 4, passwd);
	    passwd = b64from24bit(finalb[2], finalb[8], finalb[14], 4, passwd);
	    passwd = b64from24bit(finalb[3], finalb[9], finalb[15], 4, passwd);
	    passwd = b64from24bit(finalb[4], finalb[10], finalb[5], 4, passwd);
	    passwd = b64from24bit(0, 0, finalb[11], 2, passwd);
       
       return passwd.toString();
	}
	
	function b64from24bit(b2, b1, b0, outLen,
	        buffer) {
		    var B64T= "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
			// The bit masking is necessary because the JVM byte type is signed!
			var w = ((b2 << 16) & 0x00ffffff) | ((b1 << 8) & 0x00ffff) | (b0 & 0xff);
			// It's effectively a "for" loop but kept to resemble the original C code.
			var n = outLen;
			while (n-- > 0) {
				buffer = buffer.concat(B64T.charAt(w & 0x3f));
				w >>= 6;
			}
			return buffer
	}

	var bytesToWords = function (bytes) {
		for (var words = [], i = 0, b = 0; i < bytes.length; i++, b += 8)
			words[b >>> 5] |= (bytes[i] & 0xFF) << (24 - b % 32);
		return words;
	}

	var wordsToBytes = function (words) {
		var str;
		for (var bytes = [], b = 0; b < words.length * 32; b += 8){
			str = (words[b >>> 5] >>> (24 - b % 32)) & 0xFF;
			
			bytes.push(toByte(str));
		}
		return bytes;
	}
	var toByte = function(n){
		if(n>127){
			var m = n&127;
			m=m-1;
			return -(m^127);
		}
		return n;
	}
	var endian = function (n) {

		// If number given, swap endian
		if (n.constructor == Number) {
			return rotl(n,  8) & 0x00FF00FF |
			       rotl(n, 24) & 0xFF00FF00;
		}

		// Else, assume array and swap all items
		for (var i = 0; i < n.length; i++)
			n[i] = endian(n[i]);
		return n;

	}

	var rotl = function (n, b) {
		return (n << b) | (n >>> (32 - b));
	}

	// Bit-wise rotate right
	var rotr=function (n, b) {
		return (n << (32 - b)) | (n >>> b);
	}
	var MD5 = function(){
		this.arr = [];
	}
	//Auxiliary functions
	MD5._ff  = function (a, b, c, d, x, s, t) {
		var n = a + (b & c | ~b & d) + (x >>> 0) + t;
		return ((n << s) | (n >>> (32 - s))) + b;
	};
	MD5._gg  = function (a, b, c, d, x, s, t) {
		var n = a + (b & d | c & ~d) + (x >>> 0) + t;
		return ((n << s) | (n >>> (32 - s))) + b;
	};
	MD5._hh  = function (a, b, c, d, x, s, t) {
		var n = a + (b ^ c ^ d) + (x >>> 0) + t;
		return ((n << s) | (n >>> (32 - s))) + b;
	};
	MD5._ii  = function (a, b, c, d, x, s, t) {
		var n = a + (c ^ (b | ~d)) + (x >>> 0) + t;
		return ((n << s) | (n >>> (32 - s))) + b;
	};

	// Package private blocksize md5
	MD5._blocksize = 16;

	MD5._digestsize = 16;

	MD5.prototype={
		
		update:function(array){
			
			this.arr = this.arr.concat(array)
			//[49, 50, 51, 52, 53, 54, 52, 107, 103, 97, 57, 49, 50, 51, 52, 53, 54, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
		},
		_update:function(arr,start,end){
			
			this.arr = this.arr.concat(arr.slice(start,end))
			
		},
		digest:function(){
			// Convert to byte array
			message = this.arr;

			var m = bytesToWords(message),
			    l = message.length * 8,
			    a =  1732584193,
			    b = -271733879,
			    c = -1732584194,
			    d =  271733878;

			// Swap endian
			for (var i = 0; i < m.length; i++) {
				m[i] = ((m[i] <<  8) | (m[i] >>> 24)) & 0x00FF00FF |
				       ((m[i] << 24) | (m[i] >>>  8)) & 0xFF00FF00;
			}
		
			// Padding
			m[l >>> 5] |= 0x80 << (l % 32);
			m[(((l + 64) >>> 9) << 4) + 14] = l;

			// Method shortcuts
			var FF = MD5._ff,
			    GG = MD5._gg,
			    HH = MD5._hh,
			    II = MD5._ii;

			for (var i = 0; i < m.length; i += 16) {

				var aa = a,
				    bb = b,
				    cc = c,
				    dd = d;

				a = FF(a, b, c, d, m[i+ 0],  7, -680876936);
				d = FF(d, a, b, c, m[i+ 1], 12, -389564586);
				c = FF(c, d, a, b, m[i+ 2], 17,  606105819);
				b = FF(b, c, d, a, m[i+ 3], 22, -1044525330);
				a = FF(a, b, c, d, m[i+ 4],  7, -176418897);
				d = FF(d, a, b, c, m[i+ 5], 12,  1200080426);
				c = FF(c, d, a, b, m[i+ 6], 17, -1473231341);
				b = FF(b, c, d, a, m[i+ 7], 22, -45705983);
				a = FF(a, b, c, d, m[i+ 8],  7,  1770035416);
				d = FF(d, a, b, c, m[i+ 9], 12, -1958414417);
				c = FF(c, d, a, b, m[i+10], 17, -42063);
				b = FF(b, c, d, a, m[i+11], 22, -1990404162);
				a = FF(a, b, c, d, m[i+12],  7,  1804603682);
				d = FF(d, a, b, c, m[i+13], 12, -40341101);
				c = FF(c, d, a, b, m[i+14], 17, -1502002290);
				b = FF(b, c, d, a, m[i+15], 22,  1236535329);

				a = GG(a, b, c, d, m[i+ 1],  5, -165796510);
				d = GG(d, a, b, c, m[i+ 6],  9, -1069501632);
				c = GG(c, d, a, b, m[i+11], 14,  643717713);
				b = GG(b, c, d, a, m[i+ 0], 20, -373897302);
				a = GG(a, b, c, d, m[i+ 5],  5, -701558691);
				d = GG(d, a, b, c, m[i+10],  9,  38016083);
				c = GG(c, d, a, b, m[i+15], 14, -660478335);
				b = GG(b, c, d, a, m[i+ 4], 20, -405537848);
				a = GG(a, b, c, d, m[i+ 9],  5,  568446438);
				d = GG(d, a, b, c, m[i+14],  9, -1019803690);
				c = GG(c, d, a, b, m[i+ 3], 14, -187363961);
				b = GG(b, c, d, a, m[i+ 8], 20,  1163531501);
				a = GG(a, b, c, d, m[i+13],  5, -1444681467);
				d = GG(d, a, b, c, m[i+ 2],  9, -51403784);
				c = GG(c, d, a, b, m[i+ 7], 14,  1735328473);
				b = GG(b, c, d, a, m[i+12], 20, -1926607734);

				a = HH(a, b, c, d, m[i+ 5],  4, -378558);
				d = HH(d, a, b, c, m[i+ 8], 11, -2022574463);
				c = HH(c, d, a, b, m[i+11], 16,  1839030562);
				b = HH(b, c, d, a, m[i+14], 23, -35309556);
				a = HH(a, b, c, d, m[i+ 1],  4, -1530992060);
				d = HH(d, a, b, c, m[i+ 4], 11,  1272893353);
				c = HH(c, d, a, b, m[i+ 7], 16, -155497632);
				b = HH(b, c, d, a, m[i+10], 23, -1094730640);
				a = HH(a, b, c, d, m[i+13],  4,  681279174);
				d = HH(d, a, b, c, m[i+ 0], 11, -358537222);
				c = HH(c, d, a, b, m[i+ 3], 16, -722521979);
				b = HH(b, c, d, a, m[i+ 6], 23,  76029189);
				a = HH(a, b, c, d, m[i+ 9],  4, -640364487);
				d = HH(d, a, b, c, m[i+12], 11, -421815835);
				c = HH(c, d, a, b, m[i+15], 16,  530742520);
				b = HH(b, c, d, a, m[i+ 2], 23, -995338651);

				a = II(a, b, c, d, m[i+ 0],  6, -198630844);
				d = II(d, a, b, c, m[i+ 7], 10,  1126891415);
				c = II(c, d, a, b, m[i+14], 15, -1416354905);
				b = II(b, c, d, a, m[i+ 5], 21, -57434055);
				a = II(a, b, c, d, m[i+12],  6,  1700485571);
				d = II(d, a, b, c, m[i+ 3], 10, -1894986606);
				c = II(c, d, a, b, m[i+10], 15, -1051523);
				b = II(b, c, d, a, m[i+ 1], 21, -2054922799);
				a = II(a, b, c, d, m[i+ 8],  6,  1873313359);
				d = II(d, a, b, c, m[i+15], 10, -30611744);
				c = II(c, d, a, b, m[i+ 6], 15, -1560198380);
				b = II(b, c, d, a, m[i+13], 21,  1309151649);
				a = II(a, b, c, d, m[i+ 4],  6, -145523070);
				d = II(d, a, b, c, m[i+11], 10, -1120210379);
				c = II(c, d, a, b, m[i+ 2], 15,  718787259);
				b = II(b, c, d, a, m[i+ 9], 21, -343485551);

				a = (a + aa) >>> 0;
				b = (b + bb) >>> 0;
				c = (c + cc) >>> 0;
				d = (d + dd) >>> 0;

			}

			return wordsToBytes(endian([a, b, c, d]));

		}
	}
	
	
	return {
		"crypt":md5Crypt
	}
	
}()


		

