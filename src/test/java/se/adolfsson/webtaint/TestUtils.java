package se.adolfsson.webtaint;

import se.adolfsson.webtaint.utils.api.TaintTools;

import static junit.framework.TestCase.assertEquals;

class TestUtils {
	static void assertTaintAndLog(Object s, boolean taintExpected) {
		boolean tainted = TaintTools.isTainted(s);
		assertEquals(taintExpected, tainted);


		System.out.println(
				(tainted == taintExpected ? " OK" : "NOK") +
						" | expected " + (taintExpected ? "" : "not ") + "tainted, taint = " + tainted);
	}
}
