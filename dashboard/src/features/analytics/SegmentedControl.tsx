interface Option<T extends string> {
  value: T
  label: string
}

interface SegmentedControlProps<T extends string> {
  options: Option<T>[]
  value: T
  onChange: (value: T) => void
  testIdPrefix: string
}

export function SegmentedControl<T extends string>({
  options,
  value,
  onChange,
  testIdPrefix,
}: SegmentedControlProps<T>) {
  return (
    <div className="segmented-control" role="group">
      {options.map(opt => (
        <button
          key={opt.value}
          type="button"
          className={[
            'segmented-control__option',
            value === opt.value ? 'segmented-control__option--active' : '',
          ]
            .join(' ')
            .trim()}
          onClick={() => onChange(opt.value)}
          data-testid={`${testIdPrefix}-${opt.value}`}
          aria-pressed={value === opt.value}
        >
          {opt.label}
        </button>
      ))}
    </div>
  )
}
