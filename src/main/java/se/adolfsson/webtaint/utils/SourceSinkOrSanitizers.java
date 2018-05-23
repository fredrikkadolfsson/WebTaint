package se.adolfsson.webtaint.utils;

import javassist.ClassPool;
import javassist.CtClass;
import javassist.NotFoundException;
import lombok.Getter;

@Getter
class SourceSinkOrSanitizers {
	private String clazz;
	private String[] methods;
	private String descriptor;

	static boolean implementsSourceOrSinkInterface(String interfazz, String className) {
		ClassPool cp = ClassPool.getDefault();

		try {
			CtClass cClass = cp.get(className);

			return cClass.subtypeOf(cp.get(interfazz));
		} catch (NotFoundException ignored) {
			// ignored
		}

		return false;
	}
}
