package io.github.aloubyansky.cryptid.model;

import com.ibm.engine.model.IValue;
import com.ibm.engine.model.context.IDetectionContext;
import com.ibm.engine.rule.IBundle;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.NodeOrigin;
import com.ibm.mapper.model.collections.AbstractAssetCollection;
import io.github.aloubyansky.cryptid.detection.CryptoEvent;
import io.github.aloubyansky.cryptid.detection.CryptoEventDetector;
import io.github.aloubyansky.cryptid.detection.Loc;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;

/**
 * Assembles the crypto model nodes of a {@link CryptoEvent} tree: translates each event's action
 * and values into nodes, and attaches the nodes of the events it leads to onto its own. The result
 * is a forest of asset trees, before reorganizing and enriching.
 *
 * <p>The rules are those of sonar-cryptography's translation of its detection stores, written
 * out so they no longer depend on its engine:
 *
 * <ul>
 *   <li>An event's own nodes are keyed by argument index, {@code -1} for its action.
 *   <li>A child's nodes attach to the parent's nodes at the child's argument index; if there are
 *       none there, to the parent's first nodes (the action's, else the lowest index's); if the
 *       parent has no nodes at all, they become the parent's nodes. A child without nodes passes
 *       the parent's nodes on to its own children.
 *   <li>Attaching a node where the parent has none of its kind adds it. Where it has one, two
 *       mergeable asset collections of the same kind merge; a detected node replaces a default or
 *       enriched one; and a different detected node adds a copy of the parent holding it, as an
 *       alternative root.
 * </ul>
 *
 * <p>Children are visited by ascending argument index, calls on the object first, in the order
 * they were attached. Where a parent has no nodes, the first child with nodes becomes the
 * parent's nodes, so attachment order matters there; {@link CryptoEventDetector} attaches calls on an
 * object in the order of the spec's {@code next} list.
 *
 * <p>Not thread-safe; one assembler per tree.
 */
final class AssetAssembler {

    /** Translates one action or value into a node, given the event's library and context. */
    @FunctionalInterface
    interface ValueTranslator {
        /**
         * Translates an action or value.
         *
         * @param library the event's library
         * @param value the action or value
         * @param context the event's context, which chooses the translator
         * @param file the source file the node is located in
         * @return the node, or empty if the translator makes none of it
         */
        Optional<INode> translate(IBundle library, IValue<Loc> value, IDetectionContext context, String file);
    }

    private final ValueTranslator translator;
    private final List<INode> alternatives = new ArrayList<>();

    /**
     * Creates an assembler for one event tree.
     *
     * @param translator translates each action and value with its context's translator
     */
    AssetAssembler(ValueTranslator translator) {
        this.translator = translator;
    }

    /**
     * Assembles the nodes of an event tree.
     *
     * @param root the root event
     * @return its nodes, then the alternative roots created while attaching
     */
    List<INode> build(CryptoEvent root) {
        final Map<Integer, List<INode>> nodes = own(root);
        visitChildren(root, nodes);
        final List<INode> result = new ArrayList<>();
        nodes.values().forEach(result::addAll);
        result.addAll(alternatives);
        return result;
    }

    /** An event's own nodes by argument index, {@code -1} for its action. */
    private Map<Integer, List<INode>> own(CryptoEvent d) {
        final Map<Integer, List<INode>> nodes = new TreeMap<>();
        d.action().ifPresent(a -> (d.model().isPresent()
                        ? OwnModels.create(d.model().get(), CryptoAssetModeler.location(d.library(), a.getLocation(), d.file()))
                        : translator.translate(d.library(), a, d.detectionContext(), d.file()))
                .ifPresent(n -> nodes.computeIfAbsent(-1, k -> new ArrayList<>()).add(n)));
        d.values().forEach((index, values) -> {
            for (IValue<Loc> v : values) {
                translator.translate(d.library(), v, d.detectionContext(), d.file())
                        .ifPresent(n -> nodes.computeIfAbsent(index, k -> new ArrayList<>()).add(n));
            }
        });
        return nodes;
    }

    private void visitChildren(CryptoEvent d, Map<Integer, List<INode>> nodes) {
        for (CryptoEvent child : d.children().getOrDefault(-1, List.of())) {
            attach(-1, child, nodes);
        }
        d.children().forEach((index, children) -> {
            if (index != -1) {
                children.forEach(child -> attach(index, child, nodes));
            }
        });
    }

    private void attach(int index, CryptoEvent child, Map<Integer, List<INode>> parentNodes) {
        Map<Integer, List<INode>> childNodes = own(child);
        final List<INode> flat = new ArrayList<>();
        childNodes.values().forEach(flat::addAll);
        if (!flat.isEmpty()) {
            final List<INode> atIndex = parentNodes.get(index);
            if (atIndex != null) {
                append(atIndex, flat);
            } else if (parentNodes.isEmpty()) {
                parentNodes.put(-1, flat);
            } else {
                append(parentNodes.values().iterator().next(), flat);
            }
        }
        if (childNodes.isEmpty()) {
            childNodes = parentNodes;
        }
        visitChildren(child, childNodes);
    }

    private void append(List<INode> parents, List<INode> children) {
        for (INode parent : List.copyOf(parents)) {
            for (INode child : children) {
                merge(parent, child);
            }
        }
    }

    private void merge(INode parent, INode child) {
        final Optional<INode> existing = parent.hasChildOfType(child.getKind());
        if (existing.isEmpty()) {
            parent.put(child);
            return;
        }
        final INode e = existing.get();
        if (child instanceof AbstractAssetCollection c && e instanceof AbstractAssetCollection ec
                && c.isMergeable() && c.getClass().equals(ec.getClass())) {
            final List<INode> all = new ArrayList<>(ec.getCollection());
            all.addAll(c.getCollection());
            final AbstractAssetCollection merged = ec.createMerged(all);
            ((INode) c).getChildren().values().forEach(merged::put);
            ((INode) ec).getChildren().values().forEach(merged::put);
            parent.put(merged);
            return;
        }
        if (!e.is(child.getKind()) || e.asString().equals(child.asString())) {
            return;
        }
        if (e.getOrigin() == NodeOrigin.DEFAULT || e.getOrigin() == NodeOrigin.ENRICHED) {
            if (child.getOrigin() == NodeOrigin.DETECTED) {
                parent.put(child);
            }
        } else if (child.getOrigin() != NodeOrigin.DEFAULT && child.getOrigin() != NodeOrigin.ENRICHED) {
            final INode alternative = parent.deepCopy();
            alternative.put(child);
            alternatives.add(alternative);
        }
    }
}
