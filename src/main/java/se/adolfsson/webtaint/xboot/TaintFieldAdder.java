package se.adolfsson.webtaint.xboot;

import javassist.*;
import se.adolfsson.webtaint.utils.SourcesSinksOrSanitizers;
import se.adolfsson.webtaint.utils.TaintUtils;
import se.adolfsson.webtaint.utils.api.TaintException;
import se.adolfsson.webtaint.utils.api.TaintTools;
import se.adolfsson.webtaint.utils.api.Taintable;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.HashMap;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import static se.adolfsson.webtaint.utils.SourcesSinksOrSanitizers.*;


/**
 * We need to prepare a modification of java.lang.Stringuilder ahead of time that we can put on the bootclasspath,
 * since we are unable to add fields to any class that the java agent itself depends on (we can't get to them before
 * they are loaded the first time).
 */
public class TaintFieldAdder {
	private HashMap<String, CtClass> propagatingDataTypes = new HashMap<>();

	public static void main(String[] args) {
		System.out.println();
		System.out.println("Staring TaintFieldAdder");

		new TaintFieldAdder().run();
		System.out.println();
	}

	private void run() {
		try {
			ClassPool cp = ClassPool.getDefault();

			cp.importPackage(TaintUtils.class.getName());
			cp.importPackage(TaintTools.class.getName());

			addTaintableToClass(cp, String.class.getName());
			addTaintableToClass(cp, StringBuffer.class.getName());
			addTaintableToClass(cp, StringBuilder.class.getName());

			writeClass(cp, Taintable.class.getName());
			writeClass(cp, TaintException.class.getName());
			writeClass(cp, TaintTools.class.getName());
			writeClass(cp, TaintUtils.class.getName());

			String JREPath = System.getProperty("java.home").concat("/lib/rt.jar");
			addSourcesSinksAndSanitizorsRT(cp, JREPath);
		} catch (IOException | CannotCompileException | NotFoundException e) {
			e.printStackTrace();
		}
	}

	private void addSourcesSinksAndSanitizorsRT(ClassPool cp, String path) {
		try {
			SourcesSinksOrSanitizers sinksOrSanitizers = new SourcesSinksOrSanitizers();

			cp.insertClassPath(path);

			ZipInputStream zip = new ZipInputStream(new FileInputStream(path));
			for (ZipEntry entry = zip.getNextEntry(); entry != null; entry = zip.getNextEntry()) {
				if (!entry.isDirectory() && entry.getName().endsWith(".class")) {
					String className = entry.getName().replace('/', '.').replaceAll(".class", "");

					CtClass ret, tmp;
					ret = propagatingDataTypes.getOrDefault(className, null);
					if ((tmp = sinksOrSanitizers.isSourceSinkOrSanitizer(getSources(), className, ret)) != null)
						ret = tmp;
					if ((tmp = sinksOrSanitizers.isSourceSinkOrSanitizer(getSinks(), className, ret)) != null)
						ret = tmp;
					if ((tmp = sinksOrSanitizers.isSourceSinkOrSanitizer(getSanitizers(), className, ret)) != null)
						ret = tmp;
					if (ret != null) writeBytes(className, ret.toBytecode());
				}
			}
		} catch (IOException | CannotCompileException | NotFoundException e) {
			e.printStackTrace();
		}
	}

	private void addTaintableToClass(ClassPool cp, String className) throws NotFoundException, CannotCompileException, IOException {
		CtClass cClass = cp.get(className);
		cClass.defrost();

		cClass.addInterface(cp.get(Taintable.class.getName()));

		addTaintVar(cClass);
		addTaintMethods(cClass);
		propagateTaintInMethods(cClass);
		propagatingDataTypes.put(className, cClass);
		writeClass(cp, className);
	}

	private void addTaintVar(CtClass cClass) throws CannotCompileException {
		cClass.addField(CtField.make("private boolean tainted;", cClass), "TaintUtils.propagateParameterTaint($0, $args)");
		cClass.addField(CtField.make("private String taintSource;", cClass));
	}

	private void addTaintMethods(CtClass cClass) throws CannotCompileException {
		cClass.addMethod(CtMethod.make("public void setTaint(boolean value, String className){ this.tainted = value; if(className != null) this.taintSource = className; }", cClass));
		cClass.addMethod(CtMethod.make("public boolean isTainted(){ return this.tainted; }", cClass));
		cClass.addMethod(CtMethod.make("public String getTaintSource(){ return this.taintSource; }", cClass));
	}

	private void propagateTaintInMethods(CtClass cClass) throws NotFoundException, CannotCompileException {
		CtMethod[] cMethods = cClass.getDeclaredMethods();
		for (CtMethod cMethod : cMethods) {
			if (isNotStatic(cMethod) &&
					isNotNative(cMethod) &&
					isNotAbstract(cMethod) &&
					!cMethod.getName().equals("setTaint") &&
					!cMethod.getName().equals("isTainted") &&
					!cMethod.getName().equals("setTaintSource") &&
					!cMethod.getName().equals("getTaintSource")) {

				CtClass returnType = cMethod.getReturnType();
				if (returnType.subtypeOf(ClassPool.getDefault().get(Taintable.class.getName()))) {
					cMethod.insertAfter("{ Object ret = TaintUtils.propagateParameterTaintObject($0, $args); if(ret != null) $_.setTaint(TaintUtils.isTainted(ret), TaintUtils.getTaintSource(ret)); }");
				}

				if (cMethod.getParameterTypes().length > 0) {
					cMethod.insertBefore("{ Object ret = TaintUtils.propagateParameterTaintObject($0, $args); if(ret != null) $0.setTaint(TaintUtils.isTainted(ret), TaintUtils.getTaintSource(ret)); }");
				}
			}
		}
	}

	private void writeClass(ClassPool cp, String className) throws IOException, CannotCompileException, NotFoundException {
		CtClass cClass = cp.get(className);
		byte[] bytes = cClass.toBytecode();

		writeBytes(className, bytes);
	}

	private void writeBytes(String className, byte[] bytes) throws IOException {
		System.out.println("Added taint to: " + className + " " + bytes.length);

		String s = className.replace(".", "/");
		File f = new File("build/taint/" + s + ".class");
		f.getParentFile().mkdirs();
		FileOutputStream fos = new FileOutputStream(f);

		fos.write(bytes);
		fos.flush();
		fos.close();
	}
}
