package ab2.impl.Nachnamen;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

import ab2.ElGamalSig;
import sun.plugin2.message.Message;

public class ElGamalSigImpl implements ElGamalSig {

	@Override
	public BigInteger generatePrime(int n) {

		Random rnd = new Random();
		BigInteger q;
		BigInteger p;

		while (true)
		{
			q = BigInteger.probablePrime(n, rnd);
			p = q.add(q).add(BigInteger.ONE);

			if (p.isProbablePrime(100))
				return p;
		}
	}

	@Override
	public BigInteger generateGenerator(BigInteger p) {
		Random r = new Random();

		BigInteger a;
		BigInteger two = BigInteger.ONE.add(BigInteger.ONE);

		while (true)
		{
			a = new BigInteger(p.bitLength(), r);

			if (a.compareTo(p) < 0)
			{
				if (a.modPow(two, p).compareTo(BigInteger.ONE) != 0)
				{
					if (a.modPow(p, p).compareTo(BigInteger.ONE) != 0)
					{
						return a;
					}
				}
			}
		}
	}


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
		Random rand = new Random();
		BigInteger k ,r ,s ,h;
		BigInteger pMinusOne = p.subtract(BigInteger.ONE);
		// When we send a message

		do {
			do {

				// pick a random k.
				k = keyHelperMethod(p);
				h = k.gcd(pMinusOne);
				//found if ggt(k, p-1) not 1 and k > 1
			} while (h.compareTo(BigInteger.ONE) != 0);
			System.out.println("k : " + k);

			//calc r = (r^k) mod p
			System.out.println("g : " + g);
			System.out.println("p : " + p);

			r = g.modPow(k, p);
			System.out.println("r : " + r);

			//message bytes to BigInteger
			BigInteger m = new BigInteger(1, message);
			System.out.println("m : " + m);

			byte[] asdf = null;
			try {
				MessageDigest md = MessageDigest.getInstance("SHA");
				md.update(message);
				asdf = md.digest();

			} catch (NoSuchAlgorithmException e) {
				e.printStackTrace();
			}

			BigInteger hm = new BigInteger(1, asdf);

			System.out.println("hash m : " + hm);
			////generate message hash
			//BigInteger hm = BigInteger.valueOf(m.hashCode());
			//System.out.println("hash m : " + hm);

			//generate signature
			BigInteger dmr = d.multiply(r);
			BigInteger hmmdr = hm.subtract(dmr);
			BigInteger kpm1 = k.modInverse(pMinusOne);
			s = hmmdr.multiply(kpm1);
			s = s.mod(pMinusOne);
			System.out.println("s : " + s);
			//if s = 0 try again
		}while(s.compareTo(BigInteger.ZERO) == 0);




		return new ElGamalSignature(r.toByteArray(), s.toByteArray());
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

		byte[] asdf = null;
		try {
			MessageDigest md = MessageDigest.getInstance("SHA");
			md.update(message);
			asdf = md.digest();

		} catch (NoSuchAlgorithmException x) {
			x.printStackTrace();
		}

		BigInteger hm = new BigInteger(1, asdf);

		System.out.println("hash m : " + hm);

		//generate message hash
		//BigInteger hm = BigInteger.valueOf(m.hashCode());
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