type MiniTabOption<T extends string> = {
  id: T;
  label: string;
};

interface MiniTabsProps<T extends string> {
  options: MiniTabOption<T>[];
  activeId: T;
  onChange: (id: T) => void;
}

export function MiniTabs<T extends string>({
  options,
  activeId,
  onChange
}: MiniTabsProps<T>) {
  return (
    <nav className="mini-tabs">
      {options.map((option) => (
        <button
          key={option.id}
          className={`mini-tab ${activeId === option.id ? "mini-tab--active" : ""}`}
          onClick={() => onChange(option.id)}
        >
          {option.label}
        </button>
      ))}
    </nav>
  );
}
