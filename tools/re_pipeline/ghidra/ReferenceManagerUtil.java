// Shared helper for Ghidra scripts — not a standalone script.
// getReferencesTo(Address) return type differs across Ghidra versions (Reference[] vs ReferenceIterator, etc.).

import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Iterator;

/**
 * Invokes ReferenceManager.getReferencesTo(Address) via reflection and dispatches on the runtime
 * return type so scripts compile against any Ghidra install in this toolchain.
 */
public final class ReferenceManagerUtil {

    private static volatile Method getReferencesToMethod;

    @FunctionalInterface
    public interface ReferenceToVisitor {
        void accept(Reference ref) throws Exception;
    }

    private ReferenceManagerUtil() {
    }

    private static Method resolveGetReferencesToMethod() throws NoSuchMethodException {
        if (getReferencesToMethod == null) {
            synchronized (ReferenceManagerUtil.class) {
                if (getReferencesToMethod == null) {
                    getReferencesToMethod =
                            ReferenceManager.class.getMethod("getReferencesTo", Address.class);
                }
            }
        }
        return getReferencesToMethod;
    }

    /**
     * Invokes getReferencesTo and visits each Reference in iteration order.
     */
    public static void forEachReferenceTo(ReferenceManager refMgr, Address addr,
            ReferenceToVisitor visitor) throws Exception {
        Object result;
        try {
            result = resolveGetReferencesToMethod().invoke(refMgr, addr);
        } catch (InvocationTargetException e) {
            Throwable c = e.getCause();
            if (c instanceof Exception) {
                throw (Exception) c;
            }
            throw new RuntimeException(e.getCause());
        } catch (IllegalAccessException | NoSuchMethodException e) {
            throw new RuntimeException("getReferencesTo reflection failed", e);
        }

        if (result == null) {
            return;
        }

        if (result instanceof Reference[]) {
            for (Reference r : (Reference[]) result) {
                visitor.accept(r);
            }
            return;
        }

        if (result instanceof ReferenceIterator) {
            ReferenceIterator ri = (ReferenceIterator) result;
            while (ri.hasNext()) {
                visitor.accept(ri.next());
            }
            return;
        }

        if (result instanceof Iterator) {
            Iterator<?> it = (Iterator<?>) result;
            while (it.hasNext()) {
                Object o = it.next();
                if (o instanceof Reference) {
                    visitor.accept((Reference) o);
                }
            }
            return;
        }

        if (result instanceof Iterable) {
            for (Object o : (Iterable<?>) result) {
                if (o instanceof Reference) {
                    visitor.accept((Reference) o);
                }
            }
            return;
        }

        throw new IllegalStateException(
                "getReferencesTo returned unsupported type: " + result.getClass().getName());
    }
}
