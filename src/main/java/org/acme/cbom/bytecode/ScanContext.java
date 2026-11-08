package org.acme.cbom.bytecode;

import com.ibm.engine.language.IScanContext;
import org.sonar.api.batch.fs.InputFile;

/**
 * Provides the file path to sonar-cryptography's translation, which reads it from the detection
 * store's scan context.
 *
 * @param path the source file path, prefixed with the artifact path
 */
record ScanContext(String path) implements IScanContext<Object, Loc> {

    @Override
    public void reportIssue(Object rule, Loc tree, String message) {}

    @Override
    public InputFile getInputFile() {
        throw new UnsupportedOperationException();
    }

    @Override
    public String getFilePath() {
        return path;
    }

    @Override
    public String getRelativePath() {
        return path;
    }
}
