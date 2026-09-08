namespace Indago.Fixtures;
// Compile-only fixture: analysis must never run its initializer or methods.
public static class ManagedFixture
{
    static ManagedFixture() => throw new System.InvalidOperationException("Target initializer must not run");
    public static int Select(int value) => value > 7 ? value + 3 : value - 2;
    public static string Marker() => "indago-managed-static-fixture";
}
