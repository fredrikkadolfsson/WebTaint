package se.adolfsson.webtaint.utils;

import com.fasterxml.jackson.databind.ObjectMapper;
import javassist.*;
import lombok.Getter;
import lombok.Setter;
import se.adolfsson.webtaint.utils.api.TaintTools;
import se.adolfsson.webtaint.utils.api.Taintable;

import java.io.IOException;
import java.net.URL;
import java.util.List;

import static se.adolfsson.webtaint.utils.SourceSinkOrSanitizers.implementsSourceOrSinkInterface;
import static se.adolfsson.webtaint.utils.SourcesSinksOrSanitizersEnum.*;

@Getter
public class SourcesSinksOrSanitizers {
	private List<SourceSinkOrSanitizers> classes;
	private List<SourceSinkOrSanitizers> interfaces;
	@Setter
	private SourcesSinksOrSanitizersEnum SourcesSinksOrSanitizersEnum;
	@Setter
	private ClassPool cp;

	public SourcesSinksOrSanitizers() {
		cp = new ClassPool();
		cp.appendSystemPath();
	}


	public static boolean isNotNative(CtMethod method) {
		return !Modifier.isNative(method.getModifiers());
	}

	public static boolean isNotStatic(CtMethod method) {
		return !Modifier.isStatic(method.getModifiers());
	}

	public static boolean isNotAbstract(CtMethod method) {
		return !Modifier.isAbstract(method.getModifiers());
	}

	private static SourcesSinksOrSanitizers getSourcesOrSinks(String fileName) throws IOException {
		URL fileUrl = ClassLoader.getSystemClassLoader().getResource(fileName);
		ObjectMapper mapper = new ObjectMapper();

		return mapper.readValue(fileUrl, SourcesSinksOrSanitizers.class);
	}

	private static boolean isSourceSinkOrSanitizerClass(SourcesSinksOrSanitizers sourcesSinksOrSanitizers,
	                                                    String className) {
		return isSourceSinkOrSanitizer(sourcesSinksOrSanitizers.getClasses(), className);
	}

	private static boolean isSourceSinkOrSanitizer(List<SourceSinkOrSanitizers> sourcesOrSinks, String className) {
		for (SourceSinkOrSanitizers source : sourcesOrSinks) {
			if (className.equals(source.getClazz()))
				return true;
		}

		return false;
	}

	private static void print(String content) {
		boolean debug = false;
		if (debug)
			System.out.println(content);
	}

	public static SourcesSinksOrSanitizers getSinks() throws IOException {
		SourcesSinksOrSanitizers ret = getSourcesOrSinks("sinks.json");
		ret.setSourcesSinksOrSanitizersEnum(SINKS);
		return ret;
	}

	public static SourcesSinksOrSanitizers getSanitizers() throws IOException {
		SourcesSinksOrSanitizers ret = getSourcesOrSinks("sanitizers.json");
		ret.setSourcesSinksOrSanitizersEnum(SANITIZERS);
		return ret;
	}

	public static SourcesSinksOrSanitizers getSources() throws IOException {
		SourcesSinksOrSanitizers ret = getSourcesOrSinks("sources.json");
		ret.setSourcesSinksOrSanitizersEnum(SOURCES);
		return ret;
	}

	private String isSuperSourceOrSink(SourcesSinksOrSanitizers sourcesSinksOrSanitizers, String className) {
		String ret;
		if (isSourceSinkOrSanitizerClass(sourcesSinksOrSanitizers, className))
			return className;
		else if ((ret = usesInterface(sourcesSinksOrSanitizers, className)) != null)
			return ret;
		else if ((ret = extendsSourceOrSinkClass(sourcesSinksOrSanitizers, className)) != null)
			return ret;
		else
			return null;
	}

	private String usesInterface(SourcesSinksOrSanitizers sourcesSinksOrSanitizers, String className) {
		boolean ret;
		for (SourceSinkOrSanitizers interfazz : sourcesSinksOrSanitizers.getInterfaces()) {
			ret = implementsSourceOrSinkInterface(interfazz.getClazz(), className);
			if (ret)
				return interfazz.getClazz();
		}

		return extendsSourceOrSinkInterface(sourcesSinksOrSanitizers, className);
	}

	private CtClass transform(CtClass cClass, SourcesSinksOrSanitizers sourcesSinksOrSanitizersIn,
	                          String className, String alteredAsClassName) {

		try {
			print("########################################");
			print("");
			print("Transforming "
					+ (sourcesSinksOrSanitizersIn.getSourcesSinksOrSanitizersEnum() == SOURCES ? "Source: " : "")
					+ (sourcesSinksOrSanitizersIn.getSourcesSinksOrSanitizersEnum() == SINKS ? "Sink: " : "")
					+ (sourcesSinksOrSanitizersIn.getSourcesSinksOrSanitizersEnum() == SANITIZERS ? "Sanitizer: " : "")
					+ className + (className.equals(alteredAsClassName) ? "" : " as " + alteredAsClassName));

			if (cClass == null)
				cClass = cp.getOrNull(className);
			if (cClass == null) {
				print("\tClass not loaded");
				print("");
				print("########################################");
				return null;
			}

			print("Methods: ");
			cClass.defrost();

			List<SourceSinkOrSanitizers> sourceSinkOrSanitizers = (cp.get(alteredAsClassName).isInterface()
					? sourcesSinksOrSanitizersIn.getInterfaces()
					: sourcesSinksOrSanitizersIn.getClasses());

			SourceSinkOrSanitizers source = sourceSinkOrSanitizers.stream()
					.filter(src -> src.getClazz().equals(alteredAsClassName)).findFirst().get();

			String[] methods = source.getMethods();

			if (methods[0].equals("*")) {
				CtMethod[] cMethods = cClass.getDeclaredMethods();
				methods = new String[cMethods.length];

				int idx = 0;
				for (CtMethod cMethod : cMethods) {
					methods[idx++] = cMethod.getName();
				}
			}

			for (String method : methods) {
				print("\t" + method);

				CtMethod[] cMethods = cClass.getDeclaredMethods(method);

				if (cMethods.length > 0) {
					for (CtMethod cMethod : cMethods) {
						if (isNotNative(cMethod) && isNotAbstract(cMethod)) {
							CtClass returnType = cMethod.getReturnType();
							if (sourcesSinksOrSanitizersIn.getSourcesSinksOrSanitizersEnum() == SOURCES) {
								if (returnType.subtypeOf(cp.get(Taintable.class.getName()))) {
									cp.importPackage(TaintUtils.class.getName());
									cp.importPackage(TaintTools.class.getName());

									if (isNotStatic(cMethod))
										cMethod.insertAfter("{ TaintUtils.addTaintToMethod($0, $_, \"" + className + "\"); }");
									else cMethod.insertAfter("{ TaintUtils.addTaintToMethod(null, $_, \"" + className + "\"); }");
									print("\t\tSource Defined");
								} else
									print("\t\t Untaintable return type: " + returnType.getName());

							} else if (sourcesSinksOrSanitizersIn.getSourcesSinksOrSanitizersEnum() == SINKS) {
								cp.importPackage(TaintUtils.class.getName());
								cp.importPackage(TaintTools.class.getName());

								if (isNotStatic(cMethod))
									cMethod.insertBefore("{ TaintUtils.assertNonTaint($0, $args, \"" + className + "\"); }");
								else cMethod.insertBefore("{ TaintUtils.assertNonTaint(null, $args, \"" + className + "\"); }");
								print("\t\tSink Defined");

							} else if (sourcesSinksOrSanitizersIn.getSourcesSinksOrSanitizersEnum() == SANITIZERS) {
								cp.importPackage(TaintUtils.class.getName());
								cp.importPackage(TaintTools.class.getName());
								cMethod.insertAfter("{ TaintUtils.detaintMethodReturn($_); }");
								print("\t\tSanitizer Defined");

							} else
								print("\t\tError in Enum");
						} else
							print("\t\tCan't taint native method");
					}
				} else
					print("\t\tDo not exist in class");
			}

			print("");
			print("########################################");
			print("");

			return cClass;

		} catch (NotFoundException | CannotCompileException e) {
			e.printStackTrace();
			return null;
		}
	}

	private String extendsSourceOrSinkClass(SourcesSinksOrSanitizers sourcesSinksOrSanitizers, String className) {

		try {
			CtClass cClass = cp.get(className);
			CtClass scClass = cClass.getSuperclass();

			if (scClass != null)
				return isSuperSourceOrSink(sourcesSinksOrSanitizers, scClass.getName());
		} catch (NotFoundException ignored) {
		}

		return null;
	}

	private String extendsSourceOrSinkInterface(SourcesSinksOrSanitizers sourcesSinksOrSanitizers, String clazz) {
		boolean ret;
		for (SourceSinkOrSanitizers interfazz : sourcesSinksOrSanitizers.getInterfaces()) {

			try {
				CtClass cClass = cp.get(clazz);
				CtClass ecClass = cp.get(interfazz.getClazz());

				ret = cClass.subtypeOf(ecClass);

				if (ret)
					return interfazz.getClazz();
			} catch (NotFoundException ignored) {
				// ignore
			}
		}
		return null;
	}

	public CtClass isSourceSinkOrSanitizer(SourcesSinksOrSanitizers sourcesSinksOrSanitizers, String className,
	                                       CtClass cClass) {

		try {
			if (cp.get(className).isInterface())
				return null;
		} catch (NotFoundException ignored) {
			return null;
		}

		String alteredAsClassName;
		if (isSourceSinkOrSanitizerClass(sourcesSinksOrSanitizers, className))
			return transform(cClass, sourcesSinksOrSanitizers, className, className);
		else if ((alteredAsClassName = usesInterface(sourcesSinksOrSanitizers, className)) != null)
			return transform(cClass, sourcesSinksOrSanitizers, className, alteredAsClassName);
		else if ((alteredAsClassName = extendsSourceOrSinkClass(sourcesSinksOrSanitizers, className)) != null)
			return transform(cClass, sourcesSinksOrSanitizers, className, alteredAsClassName);
		else return null;
	}
}
