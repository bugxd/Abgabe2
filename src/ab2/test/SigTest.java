package ab2.test;

import java.math.BigInteger;

import org.junit.Assert;
import org.junit.Test;

import ab2.ElGamalSig;
import ab2.ElGamalSig.ElGamalSignature;
import ab2.impl.Nachnamen.ElGamalSigImpl;

public class SigTest {

	public static final int BIT_LENGTH = 20;

	ElGamalSig tools = new ElGamalSigImpl();

	@Test
	public void testGoodSignature10times()
	{
		for(int i = 0; i < 10; i++)
		{
			System.out.println(testSignatureZeugsBad2() + "\n\n\n");
			System.out.println("------------------------------------------------------------------");
		}
	}

	public boolean testSignatureZeugs()
	{
		byte[] message = "Das ist ein SysSec-Test".getBytes();

		BigInteger p = tools.generatePrime(BIT_LENGTH);
		BigInteger g = tools.generateGenerator(p);
		BigInteger d = tools.generatePrivatePart(p);
		BigInteger e = tools.generatePublicPart(p, g, d);

		ElGamalSignature sig = tools.sign(message, p, g, d);

		return tools.verify(message, sig, p, g, e);
	}

	public boolean testSignatureZeugsBad1()
	{
		byte[] message = "Das ist ein SysSec-Test".getBytes();

		BigInteger p = tools.generatePrime(BIT_LENGTH);
		BigInteger g = tools.generateGenerator(p);
		BigInteger d = tools.generatePrivatePart(p);
		BigInteger e = tools.generatePublicPart(p, g, d);

		ElGamalSignature sig = tools.sign(message, p, g, d);

		byte[] s = sig.getS();
		s[0] = (byte) (s[0] ^ (byte) 0xff);
		sig.setS(s);

		return tools.verify(message, sig, p, g, e);
	}

	public boolean testSignatureZeugsBad2()
	{
		byte[] message = "Das ist ein SysSec-Test".getBytes();

		BigInteger p = tools.generatePrime(BIT_LENGTH);
		BigInteger g = tools.generateGenerator(p);
		BigInteger d = tools.generatePrivatePart(p);
		BigInteger e = tools.generatePublicPart(p, g, d);

		ElGamalSignature sig = tools.sign(message, p, g, d);

		byte[] s = sig.getS();
		sig.setS(sig.getR());
		sig.setR(s);

		return tools.verify(message, sig, p, g, e);
	}


	@Test
	public void testGoodSignature() {

		byte[] message = "Das ist ein SysSec-Test".getBytes();

		BigInteger p = tools.generatePrime(BIT_LENGTH);
		BigInteger g = tools.generateGenerator(p);
		BigInteger d = tools.generatePrivatePart(p);
		BigInteger e = tools.generatePublicPart(p, g, d);

		ElGamalSignature sig = tools.sign(message, p, g, d);

		Assert.assertEquals(true, tools.verify(message, sig, p, g, e));
	}

	@Test
	public void testBadSignature1() {
//test
		byte[] message = "Das ist ein SysSec-Test".getBytes();

		BigInteger p = tools.generatePrime(BIT_LENGTH);
		BigInteger g = tools.generateGenerator(p);
		BigInteger d = tools.generatePrivatePart(p);
		BigInteger e = tools.generatePublicPart(p, g, d);

		ElGamalSignature sig = tools.sign(message, p, g, d);

		byte[] s = sig.getS();
		s[0] = (byte) (s[0] ^ (byte) 0xff);
		sig.setS(s);

		Assert.assertEquals(false, tools.verify(message, sig, p, g, e));
	}

	@Test
	public void testBadSignature2() {

		byte[] message = "Das ist ein SysSec-Test".getBytes();

		BigInteger p = tools.generatePrime(BIT_LENGTH);
		BigInteger g = tools.generateGenerator(p);
		BigInteger d = tools.generatePrivatePart(p);
		BigInteger e = tools.generatePublicPart(p, g, d);

		ElGamalSignature sig = tools.sign(message, p, g, d);

		byte[] s = sig.getS();
		sig.setS(sig.getR());
		sig.setR(s);

		Assert.assertEquals(false, tools.verify(message, sig, p, g, e));
	}

	// Primzahl sollte der Form p=2q+1 sein (Test kann theoretisch auch
	// fehlschlagen, obwohl p passend gewählt wurde)
	@Test
	public void testPrime() {
		BigInteger p = tools.generatePrime(BIT_LENGTH);

		Assert.assertEquals(true,
				p.subtract(BigInteger.valueOf(1)).divide(BigInteger.valueOf(2))
						.isProbablePrime(100));
	}

	@Test
	public void testmygenerator1000times()
	{
		for (int i = 0; i < 1000; i++)
			testmygenerator();
	}


	@Test
	public void testmygenerator()
	{
		BigInteger p = tools.generatePrime(BIT_LENGTH);
		BigInteger g = tools.generateGenerator(p);

		BigInteger q = p.subtract(BigInteger.valueOf(1)).divide(
				BigInteger.valueOf(2));

		System.out.println(g.toString());

		Assert.assertEquals(true, g1test(q, p, g) || g2test(q, p, g));
	}


	public boolean g1test(BigInteger q, BigInteger p, BigInteger g)
	{

		// g^q und g^2 dürfen nicht 1 ergeben. Ist dies der Fall, so hat g die
		// Ordnun p-1. Sonst entweder q oder 2
		return
				!g.modPow(q, p).equals(BigInteger.valueOf(1))
						&& !g.modPow(BigInteger.valueOf(2), p).equals(
						BigInteger.valueOf(1));
	}

	public boolean g2test(BigInteger q, BigInteger p, BigInteger g)
	{

		// g^q ergibt 1. Somit ist die Ordnung des Generator q (weil q eine Primzahl ist, kann es keine weiteren Untergruppen geben)
		return g.modPow(q, p).equals(BigInteger.valueOf(1));
	}



	// Annahme: Primzahl ist der Form p=2q+1. Generator soll Untergruppe der
	// Ordnung p-1 bilden
	@Test
	public void testGenerator1() {
		BigInteger p = tools.generatePrime(BIT_LENGTH);
		BigInteger g = tools.generateGenerator(p);

		BigInteger q = p.subtract(BigInteger.valueOf(1)).divide(
				BigInteger.valueOf(2));

		System.out.println(g.toString());

		// g^q und g^2 dürfen nicht 1 ergeben. Ist dies der Fall, so hat g die
		// Ordnun p-1. Sonst entweder q oder 2
		Assert.assertEquals(
				true,
				!g.modPow(q, p).equals(BigInteger.valueOf(1))
						&& !g.modPow(BigInteger.valueOf(2), p).equals(
								BigInteger.valueOf(1)));
	}

	// Annahme: Primzahl ist der Form p=2q+1. Generator soll Untergruppe der
	// Ordnung q bilden
	@Test
	public void testGenerator2() {
		BigInteger p = tools.generatePrime(BIT_LENGTH);
		BigInteger g = tools.generateGenerator(p);

		BigInteger q = p.subtract(BigInteger.valueOf(1)).divide(BigInteger.valueOf(2));

		// g^q ergibt 1. Somit ist die Ordnung des Generator q (weil q eine Primzahl ist, kann es keine weiteren Untergruppen geben)
		Assert.assertEquals(true,g.modPow(q, p).equals(BigInteger.valueOf(1)));
	}
}
