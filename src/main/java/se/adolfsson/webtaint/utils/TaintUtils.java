package se.adolfsson.webtaint.utils;

import se.adolfsson.webtaint.utils.api.Taintable;

import static se.adolfsson.webtaint.utils.api.TaintTools.*;

public class TaintUtils {
	public static boolean propagateParameterTaint(Object s, Object[] args) {
		Object ret = propagateParameterTaintObject(s, args);

		if (ret != null) ((Taintable) ret).isTainted();

		return false;
	}

	public static boolean isTainted(Object s) {
		return ((Taintable) s).isTainted();
	}

	public static String getTaintSource(Object s) {
		return ((Taintable) s).getTaintSource();
	}

	public static Object propagateParameterTaintObject(Object s, Object[] args) {
		if (((Taintable) s).isTainted()) return s;

		for (Object arg : args) {
			if (arg instanceof Taintable) {
				if (((Taintable) arg).isTainted()) return arg;
			}
		}

		return null;
	}

	public static void addTaintToMethod(Object s, Object ret, String className) {
		if (s != null) taint(s, className);
		if (ret != null) taint(ret, className);
	}

	public static void assertNonTaint(Object s, Object[] args, String className) {
		if (s != null) checkTaint(s, className);
		for (Object arg : args) checkTaint(arg, className);
	}

	public static void detaintMethodReturn(Object ret) {
		detaint(ret);
	}
}
