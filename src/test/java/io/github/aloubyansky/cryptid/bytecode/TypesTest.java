package io.github.aloubyansky.cryptid.bytecode;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

class TypesTest {

    @Test
    void jdkHierarchyReadsJdkClasses() {
        final Types types = Types.jdk(null, List.of());
        assertTrue(types.supertypes("javax/crypto/CipherSpi").contains("java/lang/Object"));
        // a class of a JDK module other than java.base
        assertTrue(types.supertypes("javax/xml/crypto/dsig/XMLSignature").contains("javax/xml/crypto/XMLStructure"));
    }

    @Test
    void jdkHierarchyDoesntReadTheToolsClasspath() {
        // Bouncy Castle is on this test's classpath, as cryptid's dependencies are on the runner
        // JAR's: which of them are there mustn't change a scanned class's hierarchy
        final String aes = "org/bouncycastle/crypto/engines/AESEngine";
        assertTrue(new Types(getClass().getClassLoader()).supertypes(aes).contains("org/bouncycastle/crypto/BlockCipher"));
        assertEquals(Set.of(aes), Types.jdk(null, List.of()).supertypes(aes));
    }
}
