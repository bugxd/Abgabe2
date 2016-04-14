package ab2.impl.Nachnamen;

import java.math.BigInteger;
import java.util.HashSet;
import java.util.Random;

import ab2.ElGamalSig;
import com.sun.org.apache.xpath.internal.SourceTree;

public class ElGamalSigImpl implements ElGamalSig {

	@Override
	public BigInteger generatePrime(int n) {
		BigInteger one = new BigInteger("1");
		BigInteger q = new BigInteger(n + "");
		BigInteger p = q.multiply(new BigInteger(2+"")).add(BigInteger.ONE);
		//p = 2q+1

		do {
			q = q.add(one);
			while (!q.isProbablePrime(99)){
				q = q.add(one);
			}
			p = q.multiply(new BigInteger(2+"")).add(BigInteger.ONE);

		}while(!p.isProbablePrime(99));

		return p;
	}

	@Override
	public BigInteger generateGenerator(BigInteger p) {
		Random r = new Random();

		int numtries = 0;

		// Try finding a generator at random 100 times.
		while (numtries < 1000) {

			// Here's what we're trying as the generator this time.
			BigInteger rand = new BigInteger(p.bitCount()-1,r);

			BigInteger exp = BigInteger.ONE;
			BigInteger next = rand.mod(p);

			// We exponentiate our generator until we get 1 mod p.
			while (!next.equals(BigInteger.ONE)) {
				next = (next.multiply(rand)).mod(p);
				exp = exp.add(BigInteger.ONE);
			}

			// If the first time we hit 1 is the exponent p-1, then we have
			// a generator.
			if (exp.equals(p.subtract(BigInteger.ONE)))
				return rand;
		}

		// None of the 1000 values we tried was a generator.
		return null;
	}

	@Override
	public BigInteger generatePrivatePart(BigInteger p) {
		Random r = new Random();
		BigInteger a;
		do{
			a = new BigInteger(p.bitCount()-1, r);
		}while(a.compareTo(BigInteger.ONE) < 1);
		return a;
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
				k = new BigInteger(p.bitCount() - 1, rand);
				h = k.gcd(pMinusOne);
				//found if ggt(k, p-1) not 1 and k > 1
			} while (h.compareTo(BigInteger.ONE) == 0 && k.compareTo(BigInteger.ONE) < 1);
			System.out.println("k : " + k);

			//calc r = (r^k) mod p
			r = g.modPow(k, p);
			System.out.println("r : " + r);

			//message bytes to BigInteger
			BigInteger m = new BigInteger(1, message);
			System.out.println("m : " + m);

			//generate message hash
			BigInteger hm = BigInteger.valueOf(m.hashCode());
			System.out.println("hash m : " + hm);

			//generate signature
			BigInteger dmr = d.multiply(r);
			BigInteger hmmdr = hm.subtract(dmr);
			BigInteger kpm1 = k.modInverse(p);
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
		BigInteger m =new BigInteger(1, message);

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

		//generate message hash
		BigInteger hm = BigInteger.valueOf(m.hashCode());
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