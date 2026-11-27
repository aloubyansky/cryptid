package io.github.aloubyansky.cryptid.cli;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.aloubyansky.cryptid.ArtifactCoordinates;
import io.github.aloubyansky.cryptid.CryptoAsset;
import io.github.aloubyansky.cryptid.CryptoInventory;
import io.github.aloubyansky.cryptid.bytecode.JarCache;
import io.github.aloubyansky.cryptid.scan.BytecodeScanner;
import java.nio.file.Path;
import java.util.List;
import org.bouncycastle.crypto.engines.AESEngine;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class InventoryJsonTest {

    @Test
    void roundTripsAScannedInventory(@TempDir Path tmp) throws Exception {
        final Path bcprov = Path.of(AESEngine.class.getProtectionDomain().getCodeSource().getLocation().toURI());
        final CryptoInventory inventory;
        try (JarCache jars = new JarCache()) {
            inventory = new BytecodeScanner().scan(bcprov,
                    ArtifactCoordinates.jar("org.bouncycastle", "bcprov-jdk18on", "1.78.1"), List.of(), jars, null);
        }
        assertTrue(inventory.assets().size() > 100, "assets: " + inventory.assets().size());
        final Path file = tmp.resolve("bcprov.json");
        InventoryJson.write(inventory, file);
        final CryptoInventory read = InventoryJson.read(file);

        assertEquals(inventory.artifacts(), read.artifacts());
        assertEquals(inventory.assets(), read.assets());
        for (int i = 0; i < inventory.assets().size(); i++) {
            final CryptoAsset a = inventory.assets().get(i);
            final CryptoAsset b = read.assets().get(i);
            assertEquals(a.occurrences(), b.occurrences(), a.name());
            assertEquals(a.dependsOn(), b.dependsOn(), a.name());
        }
    }
}
