namespace Indago.Dependency;
public static class Values {
    static Values() => throw new System.InvalidOperationException("Static inspection must never execute this initializer");
    public static int Add(int x) => x + 17;
}
