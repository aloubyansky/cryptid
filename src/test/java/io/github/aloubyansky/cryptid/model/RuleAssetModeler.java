package io.github.aloubyansky.cryptid.model;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.context.IDetectionContext;
import com.ibm.engine.rule.IBundle;
import com.ibm.mapper.ITranslator;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.utils.DetectionLocation;
import io.github.aloubyansky.cryptid.detection.Loc;
import io.github.aloubyansky.cryptid.reference.RuleDetector;
import java.util.List;
import java.util.Optional;

/**
 * The reference counterpart of {@link CryptoAssetModeler}: models {@link RuleDetector}'s detection
 * stores as crypto assets with sonar-cryptography's own translation ({@link ITranslator}), and the
 * same context translators, reorganizer rules and enricher. The spec-based pipeline, {@link
 * CryptoEventDetector} with {@link CryptoAssetModeler} and its {@link AssetAssembler}, is compared
 * with it.
 */
final class RuleAssetModeler extends ITranslator<Object, Loc, Object, Object> {

    private final CryptoAssetModeler modeler;

    RuleAssetModeler(CryptoAssetModeler modeler) {
        this.modeler = modeler;
    }

    /** Translates, reorganizes and enriches a root store tree. */
    List<INode> process(DetectionStore<Object, Loc, Object, Object> root) {
        return modeler.finish(translate(root));
    }

    @Override
    protected Optional<INode> translate(IBundle bundle, IValue<Loc> value, IDetectionContext context, String filePath) {
        return modeler.translate(bundle, value, context, filePath);
    }

    @Override
    protected DetectionLocation getDetectionContextFrom(Loc location, IBundle bundle, String filePath) {
        return new DetectionLocation(filePath, location.line(), 0, List.of(location.signature(), location.methodName()), bundle);
    }
}
