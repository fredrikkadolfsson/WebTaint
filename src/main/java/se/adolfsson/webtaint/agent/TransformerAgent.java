package se.adolfsson.webtaint.agent;

import javassist.CannotCompileException;
import javassist.CtClass;
import se.adolfsson.webtaint.utils.SourcesSinksOrSanitizers;

import java.io.IOException;
import java.lang.instrument.ClassFileTransformer;
import java.security.ProtectionDomain;

import static se.adolfsson.webtaint.utils.SourcesSinksOrSanitizers.*;

public class TransformerAgent implements ClassFileTransformer {
	@Override
	public byte[] transform(ClassLoader loader, String className,
	                        Class classBeingRedefined, ProtectionDomain protectionDomain,
	                        byte[] classfileBuffer) {

		className = className.replaceAll("/", ".");

		//if (!className.equals("org.apache.catalina.connector.RequestFacade")) return null;
		//System.out.println(className);


		try {
			SourcesSinksOrSanitizers sinksOrSanitizers = new SourcesSinksOrSanitizers();

			CtClass ret, tmp;
			ret = sinksOrSanitizers.isSourceSinkOrSanitizer(getSources(), className, null);
			if ((tmp = sinksOrSanitizers.isSourceSinkOrSanitizer(getSinks(), className, ret)) != null) ret = tmp;
			if ((tmp = sinksOrSanitizers.isSourceSinkOrSanitizer(getSanitizers(), className, ret)) != null) ret = tmp;
			if (ret != null) return ret.toBytecode();
		} catch (IOException | CannotCompileException e) {
			e.printStackTrace();
		}

		return classfileBuffer;
	}
}