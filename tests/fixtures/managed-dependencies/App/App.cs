namespace Indago.Dependency.App;
public static class Consumer { public static int Select(int x) => x > 7 ? Values.Add(x) : x - 1; }
