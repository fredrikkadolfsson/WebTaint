package se.adolfsson.webtaint.agent;

import java.lang.instrument.Instrumentation;

public class TaintAgent {
	public static void premain(String agentArgs, Instrumentation inst) {
		System.out.println("Executing taint premain.........");
		System.out.println();
		inst.addTransformer(new TransformerAgent());
	}
}