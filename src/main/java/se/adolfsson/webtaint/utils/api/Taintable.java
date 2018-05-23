package se.adolfsson.webtaint.utils.api;

public interface Taintable {
	void setTaint(boolean value, String className);

	String getTaintSource();

	boolean isTainted();
}
