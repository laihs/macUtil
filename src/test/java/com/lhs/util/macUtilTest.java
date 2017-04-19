package com.lhs.util;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

/**
 * Unit test for simple App.
 */
public class macUtilTest 
    extends TestCase
{
    /**
     * Create the test case
     *
     * @param testName name of the test case
     */
    public macUtilTest( String testName )
    {
        super( testName );
    }

    /**
     * @return the suite of tests being tested
     */
    public static Test suite()
    {
        return new TestSuite( macUtilTest.class );
    }

    /**
     * Rigourous Test :-)
     */
    public void testApp()
    {
    	String strSrc = "可以加密汉字.Oh,and english";
		System.out.println("明文：" + strSrc);
		
		// E2E90B28A3C789AFF7E015EBC74ACE4059FC2404C9DB4BD4E14399B7E27EDC2894980588BF9DB3DAE36BF8623C16B950
		String msgMac = macUtil.genMsgMac("20140111180909", "0123456789ABCDEF", "31", strSrc);
		System.out.println("密文:" + msgMac);
		
//		System.out.println("验证结果");
//		System.out.println(macUtil.verifyMsgMac("20140111180909", "0123456789ABCDEF", "31", strSrc,
//				"E2E90B28A3C789AFF7E015EBC74ACE4059FC2404C9DB4BD4E14399B7E27EDC2894980588BF9DB3DAE36BF8623C16B950"));
		
        assertTrue( macUtil.verifyMsgMac("20140111180909", "0123456789ABCDEF", "31", strSrc,msgMac) );
    }
}
