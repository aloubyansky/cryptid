package io.github.aloubyansky.cryptid.bytecode;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

/**
 * Checks that abstract values iterate their constants and origins in a fixed order, whatever the
 * order they were merged in: detection feeds constants to rules in that order, so it decides the
 * CBOM's content when a parameter has several possible values.
 */
class AValTest {

    @Test
    void constantsIterateInFixedOrder() {
        final AVal a = AVal.constant(2048, 1).merge(AVal.constant(-1, 1)).merge(AVal.constant(256, 1));
        final AVal b = AVal.constant(256, 1).merge(AVal.constant(2048, 1)).merge(AVal.constant(-1, 1));
        assertEquals(List.of(-1, 256, 2048), new ArrayList<>(a.consts()));
        assertEquals(new ArrayList<>(a.consts()), new ArrayList<>(b.consts()));
        assertEquals(a, b);
    }

    @Test
    void mixedConstantsOrderByTypeThenValue() {
        final AVal v = AVal.constant("SHA-256", 1).merge(AVal.constant(128, 1)).merge(AVal.constant("AES", 1))
                .merge(AVal.constant(64L, 2));
        assertEquals(List.of(128, 64L, "AES", "SHA-256"), new ArrayList<>(v.consts()));
    }

    @Test
    void originsIterateInAscendingOrder() {
        final AVal v = AVal.origin(42).merge(AVal.origin(7)).merge(AVal.origin(19));
        assertEquals(List.of(7, 19, 42), new ArrayList<>(v.origins()));
    }

    @Test
    void constantsCopyIsOrdered() {
        assertEquals(List.of("A", "B", "C"), new ArrayList<>(AVal.constants(Set.<Object>of("C", "A", "B")).consts()));
    }
}
