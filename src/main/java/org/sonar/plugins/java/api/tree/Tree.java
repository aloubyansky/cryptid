package org.sonar.plugins.java.api.tree;

/**
 * Empty marker interface, not SonarSource code. Two lambdas in sonar-cryptography's {@code
 * JcaGCMParameterSpec} rules are typed on sonar-java's {@code Tree}, so the JVM needs a class of
 * that name to create them, even though they never call it. {@code Loc} implements this so that
 * the lambdas' argument casts succeed. Spike-only: the upstream fix is to replace those lambdas
 * with a value factory, like the other rules use.
 */
public interface Tree {}
