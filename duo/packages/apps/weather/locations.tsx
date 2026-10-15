import { Menu } from '@doan-labs/duo-uikit'
import { Sym } from '@doan-labs/duo-uikit/sym.tsx'
import * as stylex from '@stylexjs/stylex'
import { type ReactNode, useEffect, useState } from 'react'
import {
  clock,
  condition,
  type Place,
  refresh,
  remove,
  scene,
  search,
  select,
  update,
  useForecast,
  usePreferences
} from './data.ts'
import { styles } from './styles.ts'

type Props = { onClose: () => void; temp: (value: number | undefined) => ReactNode }

/** The saved-cities list: large title, unit menu, search, one sky card per city. */
export function Locations({ onClose, temp }: Props) {
  const preferences = usePreferences()
  const [query, setQuery] = useState('')
  const [results, setResults] = useState<Place[]>([])
  const [searchState, setSearchState] = useState('')
  const [locationState, setLocationState] = useState('')
  const [menu, setMenu] = useState(false)
  useEffect(() => {
    const controller = new AbortController()
    setResults([])
    setSearchState(query.trim().length < 2 ? '' : 'Đang tìm…')
    const timer = setTimeout(async () => {
      if (query.trim().length < 2) return
      try {
        const matches = await search(query.trim(), controller.signal)
        if (!controller.signal.aborted) {
          setResults(matches)
          setSearchState(matches.length ? '' : 'Không tìm thấy thành phố nào. Thử thành phố lân cận.')
        }
      } catch {
        if (!controller.signal.aborted) setSearchState('Không tìm kiếm được. Kiểm tra kết nối hoặc thử lại.')
      }
    }, 350)
    return () => {
      clearTimeout(timer)
      controller.abort()
    }
  }, [query])
  function choose(p: Place) {
    select(p)
    onClose()
  }
  function locate() {
    if (!navigator.geolocation) {
      setLocationState('Trình duyệt này không cho phép lấy vị trí. Hãy tìm thành phố thủ công.')
      return
    }
    setLocationState('Đang tìm vị trí của bạn…')
    navigator.geolocation.getCurrentPosition(
      (position) => {
        const { latitude, longitude } = position.coords
        const p = {
          id: `local:${latitude.toFixed(4)},${longitude.toFixed(4)}`,
          name: 'Vị trí của tôi',
          region: `${latitude.toFixed(2)}°, ${longitude.toFixed(2)}°`,
          latitude,
          longitude
        }
        select(p)
        void refresh(p, true)
        onClose()
      },
      () =>
        setLocationState(
          'Không lấy được quyền vị trí. Cho phép vị trí trong trình duyệt, hoặc tìm thành phố thủ công.'
        ),
      { timeout: 10000, maximumAge: 300000 }
    )
  }
  const units = [
    ['C', 'Độ C', '°C'],
    ['F', 'Độ F', '°F']
  ] as const
  return (
    <div {...stylex.props(styles.scroll, styles.scrollbar)}>
      <div {...stylex.props(styles.listHead)}>
        <h1 {...stylex.props(styles.listTitle)}>Thời tiết</h1>
        <div {...stylex.props(styles.menuWrap)}>
          <button
            type="button"
            aria-label="Thêm tùy chọn"
            aria-expanded={menu}
            onClick={() => setMenu(!menu)}
            {...stylex.props(styles.control)}
          >
            <Sym name="more" size={20} />
          </button>
          <Menu
            open={menu}
            onClose={() => setMenu(false)}
            size={14}
            xstyle={styles.menu}
            itemStyle={styles.menuItem}
            items={[
              ...units.map(([unit, name, sign]) => ({
                label: (
                  <span>
                    {name} <span {...stylex.props(styles.muted)}>{sign}</span>
                  </span>
                ),
                name: `Chuyển sang ${name}`,
                checked: preferences.unit === unit,
                onSelect: () => update({ unit })
              })),
              {
                label: <span>Dùng vị trí hiện tại</span>,
                icon: 'location' as const,
                disabled: locationState === 'Đang tìm vị trí của bạn…',
                onSelect: locate
              }
            ]}
          />
        </div>
      </div>
      <div {...stylex.props(styles.searchBox)}>
        <span aria-hidden="true" {...stylex.props(styles.searchIcon)}>
          <Sym name="search" size={15} />
        </span>
        <input
          type="search"
          aria-label="Tìm thành phố"
          placeholder="Tìm thành phố hoặc sân bay"
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          {...stylex.props(styles.search)}
        />
      </div>
      {(locationState || searchState) && (
        <p role="status" {...stylex.props(styles.message)}>
          {locationState || searchState}
        </p>
      )}
      {query.trim().length >= 2
        ? results.map((p) => (
            <button key={p.id} type="button" onClick={() => choose(p)} {...stylex.props(styles.result)}>
              <strong {...stylex.props(styles.resultName)}>{p.name}</strong>
              <span {...stylex.props(styles.muted)}>{p.region}</span>
              <span {...stylex.props(styles.add)}>
                <Sym name="plus" size={14} />
              </span>
            </button>
          ))
        : preferences.places.map((p) => (
            <Location
              key={p.id}
              place={p}
              selected={p.id === preferences.selected}
              onChoose={() => choose(p)}
              canRemove={preferences.places.length > 1}
              temp={temp}
            />
          ))}
      <p {...stylex.props(styles.footnote)}>Địa điểm và đơn vị dùng chung cho cả hai màn hình.</p>
    </div>
  )
}

function Location({
  place,
  selected,
  onChoose,
  canRemove,
  temp
}: {
  place: Place
  selected: boolean
  onChoose: () => void
  canRemove: boolean
  temp: (value: number | undefined) => ReactNode
}) {
  const { data, error } = useForecast(place)
  const current = data?.current
  const sky = scene(current?.weather_code, current?.is_day)
  return (
    <div {...stylex.props(styles.location, styles[sky], selected && styles.locationSelected)}>
      {sky === 'clear' && <div aria-hidden="true" {...stylex.props(styles.layer, styles.glare)} />}
      {sky === 'night' && <div aria-hidden="true" {...stylex.props(styles.layer, styles.stars)} />}
      <button
        type="button"
        onClick={onChoose}
        aria-current={selected ? 'location' : undefined}
        {...stylex.props(styles.locationMain)}
      >
        <span {...stylex.props(styles.locationName)}>{place.name}</span>
        <span {...stylex.props(styles.locationTemp)}>{temp(current?.temperature_2m)}</span>
        <span {...stylex.props(styles.locationTime)}>
          {place.id.startsWith('local:')
            ? 'Vị trí của tôi'
            : data
              ? clock(Date.now() / 1000, data.timezone)
              : place.region}
        </span>
        <span {...stylex.props(styles.locationCondition)}>
          {current ? condition(current.weather_code!, current.is_day)[1] : error ? 'Không có dữ liệu' : 'Đang tải…'}
        </span>
        <span {...stylex.props(styles.locationRange)}>
          {data && (
            <>
              Cao:{temp(data.daily.temperature_2m_max?.[0])} Thấp:{temp(data.daily.temperature_2m_min?.[0])}
            </>
          )}
        </span>
      </button>
      {canRemove && (
        <button
          type="button"
          aria-label={`Xóa ${place.name}`}
          onClick={() => remove(place.id)}
          {...stylex.props(styles.control, styles.plain, styles.remove)}
        >
          <Sym name="close" size={12} />
        </button>
      )}
    </div>
  )
}
