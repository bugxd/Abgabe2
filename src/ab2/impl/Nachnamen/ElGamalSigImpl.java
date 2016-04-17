package ab2.impl.Nachnamen;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

import ab2.ElGamalSig;

public class ElGamalSigImpl implements ElGamalSig {

	@Override
	public BigInteger generatePrime(int n) {

		Random rnd = new Random();
		BigInteger q;
		BigInteger p;

		while (true)
		{
			// generate prime number q with given bit length
			q = BigInteger.probablePrime(n, rnd);
			// calculate p = 2q + 1
			p = q.add(q).add(BigInteger.ONE);

			// check, if p is prime
			if (p.isProbablePrime(100)) // if p is prime, then ...
				return p;				// return p
		}
	}

	@Override
	public BigInteger generateGenerator(BigInteger p) {
		Random r = new Random();

		BigInteger a;
		BigInteger two = BigInteger.ONE.add(BigInteger.ONE);

		while (true)
		{
			// create a (random) prime with same bitlength as p
			a = new BigInteger(p.bitLength(), r);

			// a has to be smaller than p
			if (a.compareTo(p) < 0)
			{
				// a^2 mod p must not be 1, because then it would be either 1 or p-1
				if (a.modPow(two, p).compareTo(BigInteger.ONE) != 0)
				{
					// if a^p mod p is not 1 ...
					if (a.modPow(p, p).compareTo(BigInteger.ONE) != 0)
					{
						return a; // then return a
					}
				}
			}
		}
	}

	// this method returns for a given p a random integer between 2 and p-2
	public BigInteger keyHelperMethod(BigInteger p)
	{
		Random rnd = new Random();
		BigInteger returnKey = null;

		boolean returnKeyFound = false;

		while (!returnKeyFound)
		{
			returnKey = new BigInteger(p.bitLength(), rnd);
			if (returnKey.compareTo(BigInteger.ONE) > 0 && returnKey.compareTo(p.subtract(BigInteger.ONE)) < 0)
				returnKeyFound = true;
		}

		return returnKey;
	}


	@Override
	public BigInteger generatePrivatePart(BigInteger p)
	{
		return keyHelperMethod(p);
	}

	@Override
	public BigInteger generatePublicPart(BigInteger p, BigInteger g, BigInteger d) {
		return g.modPow(d, p);
	}

	@Override
	public ElGamalSignature sign(byte[] message, BigInteger p, BigInteger g, BigInteger d) {

		BigInteger k ,r ,s ,h;
		BigInteger pMinusOne = p.subtract(BigInteger.ONE);
		// When we send a message

		do {
			do {

				// pick a random k.
				k = keyHelperMethod(p);

				// calculate ggt(k, p-1)
				h = k.gcd(pMinusOne);
				//found if ggt(k, p-1) not 1 and k > 1 (guaranteed by keyHelperMethod)
			} while (h.compareTo(BigInteger.ONE) != 0);

			//calc r = (r^k) mod p
			r = g.modPow(k, p);

			// hash message
			byte[] hashedMessage = hashBytes(message);

			// store hashed message in BigInteger
			BigInteger hm = new BigInteger(1, hashedMessage);

			//generate signature s = ( H(m) - d*r) * k^-1 (mod p-1)
			BigInteger dmr = d.multiply(r);   // d*r
			BigInteger hmmdr = hm.subtract(dmr);  // H(m) - d*r
			BigInteger kpm1 = k.modInverse(pMinusOne);  // k^-1
			s = hmmdr.multiply(kpm1);   // ( H(m) - d*r) * k^-1
			s = s.mod(pMinusOne);		// ( H(m) - d*r) * k^-1 (mod p-1)


			//if s = 0 try again
		}while(s.compareTo(BigInteger.ZERO) == 0);

		return new ElGamalSignature(r.toByteArray(), s.toByteArray());
	}

	// this method hashes input byte array via SHA and returns the hash value as byte array
	private byte[] hashBytes(byte[] message)
	{
		byte[] returnArray;

		try {
			MessageDigest md = MessageDigest.getInstance("SHA");
			md.update(message);
			returnArray = md.digest();
			return returnArray;

		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return null;
	}

	@Override
	public boolean verify(byte[] message, ElGamalSignature sig, BigInteger p, BigInteger g, BigInteger e) {

		BigInteger r =new BigInteger(1, sig.getR());
		BigInteger s =new BigInteger(1, sig.getS());

		int res = r.compareTo(BigInteger.ZERO);

		//r equals zero
		if(res == 0){
			return false;
		}
		//r smaller than zero
		if(res == -1){
			return false;
		}

		int res2 = r.compareTo(p);

		//r equals p
		if(res2 == 0){
			return false;
		}
		//r smaller than p
		if(res2 == 1){
			return false;
		}

		int res3 = s.compareTo(BigInteger.ZERO);

		//s equals zero
		if(res3 == 0){
			return false;
		}
		//s smaller than zero
		if(res3 == -1){
			return false;
		}

		int res4 = s.compareTo(p.subtract(BigInteger.ONE));

		//s equals p
		if(res4 == 0){
			return false;
		}
		//s smaller than p
		if(res4 == 1){
			return false;
		}

		byte[] hashedMessage = hashBytes(message);
		BigInteger hm = new BigInteger(1, hashedMessage);

		//calculate g^H(m)
		BigInteger x = g.modPow(hm,p);

		//calculate (y^r)(r^s)
		BigInteger epr = e.pow(r.intValue());
		BigInteger rps = r.pow(s.intValue());
		BigInteger y = epr.multiply(rps);
		y = y.mod(p);


		if(x.equals(y)){
			return true;
		}

		return false;
	}
}