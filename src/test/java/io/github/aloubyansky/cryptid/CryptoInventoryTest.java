package io.github.aloubyansky.cryptid;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import io.github.aloubyansky.cryptid.CryptoAssetProperties.Algorithm;
import io.github.aloubyansky.cryptid.CryptoAssetProperties.CryptoFunction;
import io.github.aloubyansky.cryptid.CryptoAssetProperties.MaterialType;
import io.github.aloubyansky.cryptid.CryptoAssetProperties.Primitive;
import io.github.aloubyansky.cryptid.CryptoAssetProperties.Protocol;
import io.github.aloubyansky.cryptid.CryptoAssetProperties.ProtocolType;
import io.github.aloubyansky.cryptid.CryptoAssetProperties.RelatedMaterial;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

class CryptoInventoryTest {

    private static final ArtifactCoordinates LIB = ArtifactCoordinates.jar("org.acme", "lib", "1.0");
    private static final ArtifactCoordinates APP = ArtifactCoordinates.jar("org.acme", "app", "1.0");
    private static final Algorithm SHA256 = new Algorithm(Primitive.HASH, "256", null, null, null, Set.of(CryptoFunction.DIGEST), null);
    private static final RelatedMaterial KEY = new RelatedMaterial(MaterialType.SECRET_KEY, null, null);

    private static CodeLocation at(ArtifactCoordinates artifact, int line) {
        return new CodeLocation(artifact, "org/acme/Foo.java", new MethodId("org.acme.Foo", "run", "()V"), line,
                new MethodId("java.security.MessageDigest", "getInstance", "(Ljava/lang/String;)Ljava/security/MessageDigest;"));
    }

    @Test
    void mergesAssetsOfEqualContent() {
        final CryptoInventory.Builder b = CryptoInventory.builder();
        final CryptoAsset first = b.asset("SHA-256", SHA256);
        final CryptoAsset second = b.asset("SHA-256",
                new Algorithm(Primitive.HASH, "256", null, null, null, Set.of(CryptoFunction.DIGEST), null));
        assertSame(first, second);
        b.occurrence(first, at(LIB, 1)).occurrence(second, at(LIB, 1)).occurrence(second, at(LIB, 2));
        final CryptoInventory inventory = b.build();
        assertEquals(1, inventory.assets().size());
        assertEquals(List.of(at(LIB, 1), at(LIB, 2)),
                inventory.assets().get(0).occurrences().stream().map(AssetOccurrence::location).toList());
    }

    @Test
    void keepsAssetsOfDifferentContentApart() {
        final CryptoInventory.Builder b = CryptoInventory.builder();
        assertEquals(b.asset("SHA-256", SHA256), b.asset("SHA-256", SHA256));
        b.asset("SHA-256", new Algorithm(Primitive.HASH, "256", null, null, null, Set.of(), null));
        b.asset("SHA-384", SHA256);
        assertEquals(3, b.build().assets().size());
    }

    @Test
    void linksDependenciesIncludingCycles() {
        final CryptoInventory.Builder b = CryptoInventory.builder();
        final CryptoAsset key = b.asset("secret-key", KEY);
        final CryptoAsset hmac = b.asset("HMAC-SHA256", new Algorithm(Primitive.MAC, null, null, null, null, Set.of(), null));
        b.dependency(key, hmac).dependency(hmac, key).dependency(key, hmac).dependency(key, key);
        b.build();
        assertEquals(List.of(hmac), key.dependsOn());
        assertEquals(List.of(key), hmac.dependsOn());
    }

    @Test
    void addMergesInventoriesByContent() {
        final CryptoInventory.Builder lib = CryptoInventory.builder();
        final CryptoAsset libKey = lib.asset("secret-key", KEY);
        final CryptoAsset libSha = lib.asset("SHA-256", SHA256);
        lib.occurrence(libKey, at(LIB, 1)).occurrence(libSha, at(LIB, 2)).dependency(libKey, libSha);
        lib.artifact(new ArtifactAnalysis(LIB, ArtifactAnalysis.Outcome.ANALYZED, 3, 2, 0, null));
        final CryptoInventory.Builder app = CryptoInventory.builder();
        final CryptoAsset appSha = app.asset("SHA-256", SHA256);
        final CryptoAsset tls = app.asset("TLS", new Protocol(ProtocolType.TLS, "1.3",
                List.of(new CipherSuite("TLS_AES_128_GCM_SHA256", List.of(appSha), List.of("0x13", "0x01"))), null));
        app.occurrence(appSha, at(APP, 5)).occurrence(tls, at(APP, 6));
        app.artifact(new ArtifactAnalysis(APP, ArtifactAnalysis.Outcome.ANALYZED, 1, 2, 0, null));

        final CryptoInventory merged = CryptoInventory.builder().add(lib.build()).add(app.build()).build();
        assertEquals(List.of("secret-key", "SHA-256", "TLS"), merged.assets().stream().map(CryptoAsset::name).toList());
        final CryptoAsset sha = merged.assets().get(1);
        assertEquals(List.of(at(LIB, 2), at(APP, 5)), sha.occurrences().stream().map(AssetOccurrence::location).toList());
        assertSame(sha, merged.assets().get(0).dependsOn().get(0));
        // the cipher suite refers to the merged inventory's asset
        assertSame(sha, ((Protocol) merged.assets().get(2).properties()).cipherSuites().get(0).algorithms().get(0));
        assertEquals(List.of(LIB, APP), merged.artifacts().stream().map(ArtifactAnalysis::artifact).toList());
    }

    @Test
    void rejectsForeignAssetsAndReuse() {
        final CryptoInventory.Builder other = CryptoInventory.builder();
        final CryptoAsset foreign = other.asset("SHA-256", SHA256);
        final CryptoInventory.Builder b = CryptoInventory.builder();
        b.asset("SHA-256", SHA256);
        assertThrows(IllegalArgumentException.class, () -> b.occurrence(foreign, at(LIB, 1)));
        b.build();
        assertThrows(IllegalStateException.class, () -> b.asset("MD5", SHA256));
        assertThrows(IllegalStateException.class, b::build);
    }

    @Test
    void occurrencesAreIdentifiedByLocation() {
        final CryptoInventory.Builder b = CryptoInventory.builder();
        final CryptoAsset sha = b.asset("SHA-256", SHA256);
        b.occurrence(sha, at(LIB, 1)).occurrence(sha, at(LIB, 1));
        final AssetOccurrence o = b.build().assets().get(0).occurrences().get(0);
        assertEquals(1, sha.occurrences().size());
        assertEquals(at(LIB, 1), o.location());
        assertEquals(AssetOccurrence.Reachability.UNKNOWN, o.reachability());
    }
}
