# Siber Mod — hooks (manual application)

If `apply.sh` can't apply the patch automatically (a Capri update changed
Pet.cs/Talk.cs too much), add these hooks by hand. About 11 lines total:

## 1. Field declaration (~line 350, next to the other MenuItem fields)

Below the line `private MenuItem caughtUpItem;`:

```csharp
private MenuItem blackWall;
```

## 2. Menu items (inside Menu(), below the `napItem.Click` line)

```csharp
// Black Wall: avci bridge (patch — comes via apply.sh, re-applied on updates)
blackWall = new MenuItem { Header = "Black Wall" };
MenuItem withBurp = new MenuItem { Header = "With Burp", ToggleType = MenuItemToggleType.CheckBox, IsChecked = Siber.On };
withBurp.Click += delegate { Siber.Toggle(this); };
MenuItem psychoAuto = new MenuItem { Header = "Psycho (auto)" };
MenuItem psychoSimple = new MenuItem { Header = "Simple", ToggleType = MenuItemToggleType.Radio, GroupName = "bwpsy", IsChecked = Siber.PsychoOn && Siber.PsychoMode == "simple" };
psychoSimple.Click += delegate { Siber.SetPsycho(this, "simple"); };
MenuItem psychoHard = new MenuItem { Header = "Hard", ToggleType = MenuItemToggleType.Radio, GroupName = "bwpsy", IsChecked = Siber.PsychoOn && Siber.PsychoMode == "hard" };
psychoHard.Click += delegate { Siber.SetPsycho(this, "hard"); };
MenuItem psychoOff = new MenuItem { Header = "Off", ToggleType = MenuItemToggleType.Radio, GroupName = "bwpsy", IsChecked = !Siber.PsychoOn };
psychoOff.Click += delegate { Siber.SetPsycho(this, "off"); };
psychoAuto.Items.Add(psychoSimple);
psychoAuto.Items.Add(psychoHard);
psychoAuto.Items.Add(psychoOff);
blackWall.Items.Add(withBurp);
blackWall.Items.Add(psychoAuto);
```

## 3. Add to the root menu (end of Menu(), below `menu.Items.Add(napItem);`)

```csharp
menu.Items.Add(blackWall);
```

## 4. Startup (in the Pet ctor, below the `Brain.Bin = ...` line)

```csharp
Siber.Init(this);
```

## 5. Hunt trigger (Talk.cs, inside the Typer.Submitted delegate, ~line 819)

Replace the line `if (!Typer.Secret) { pet.Hear(text); return; }` with:

```csharp
// Siber Mod hook: in Psycho, a site name goes to the hunt job; otherwise "test/scan" triggers recon (patch — comes via apply.sh)
if (!Typer.Secret) { if (Siber.MaybePsycho(text) || Siber.MaybeHunt(text)) { Typer.Hide(); return; } pet.Hear(text); return; }
```

That's all. It's enough for `Siber.cs` to sit under `cross/`; no csproj change
is needed (SDK-style project, *.cs compiles automatically).
