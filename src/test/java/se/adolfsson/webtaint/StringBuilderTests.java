package se.adolfsson.webtaint;

import org.junit.Test;
import se.adolfsson.webtaint.utils.api.TaintTools;

import static se.adolfsson.webtaint.TestUtils.assertTaintAndLog;


public class StringBuilderTests {

	@Test
	public void TaintPropagationStringBufferAppend() {
		System.out.println("##### TAINT PROPAGATION APPEND - " + StringBuilder.class.getName());

		StringBuffer tainted = new StringBuffer("StringBuilder");
		TaintTools.taint(tainted, "Test Source");
		StringBuffer notTainted = new StringBuffer("StringBuilder");

		assertTaintAndLog(tainted, true);
		assertTaintAndLog(notTainted, false);

		assertTaintAndLog(notTainted.append(notTainted), false);
		assertTaintAndLog(tainted.append(notTainted), true);
		assertTaintAndLog(notTainted.append(notTainted), false);
		assertTaintAndLog(notTainted.append(tainted), true);
		assertTaintAndLog(notTainted, true);
		assertTaintAndLog(notTainted.toString(), true);

		TaintTools.detaint(tainted);
		TaintTools.detaint(notTainted);

		System.out.println();
	}
}
