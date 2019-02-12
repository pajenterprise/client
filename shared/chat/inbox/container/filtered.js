// @flow
// The filtered inbox rows. No dividers or headers, just smallbig row items
import * as Types from '../../../constants/types/chat2'
import {memoize} from '../../../util/memoize'
import type {RowItem} from '../index.types'

const score = (lcFilter: string, lcYou: string, names: Array<string>, insertMatcher: RegExp): number => {
  // special case, no filter
  if (!lcFilter) {
    return 1
  }
  // special case, looking for yourself
  if (names.length === 1 && names[0] === lcYou) {
    return lcYou.indexOf(lcFilter) !== -1 ? 100000 : 0
  }

  const namesMinusYou = lcYou ? names.filter(n => n !== lcYou) : names
  // special case, comma search
  const filters = lcFilter.split(',').filter(Boolean)
  let filter
  if (filters.length > 1) {
    const mustExist = filters.slice(0, -1)
    const partial = filters.slice(-1)
    // In comma sep. inputs all but the last name must be exact matches
    if (!mustExist.every(m => namesMinusYou.includes(m))) {
      return 0
    }
    filter = partial[0]
  } else {
    filter = filters[0]
  }

  const {foundExact, foundPrefix, foundSub} = namesMinusYou.reduce(
    (data, p) => {
      if (p === filter) {
        data.foundExact += 1
        return data
      } else {
        const idx = p.indexOf(filter)
        if (idx === 0) {
          data.foundPrefix += 1
          return data
        } else if (idx !== -1) {
          data.foundSub += 1
          return data
        }
        return data
      }
    },
    {foundExact: 0, foundPrefix: 0, foundSub: 0}
  )

  const searchStr = namesMinusYou.join('')
  const insertionMatch = searchStr.match(insertMatcher)
  // insertionDistance = searchStr.length - filter.length
  // 1 / (insertionDistance + 1) * 20
  // 20 <= insertionScore < 0
  const insertionScore = insertionMatch ? (1 / (searchStr.length - filter.length + 1)) * 20 : 0

  let rawScore = (foundExact ? 1000 : 0) + (foundPrefix ? 100 : 0) + insertionScore + (foundSub ? 10 : 0)

  // Special case an exact match that is the only name, otherwise
  // e.g. "chris,chrisnojima" gets a higher score than "chris", when
  // input is "chris" -- (1000 + 100) vs. (1000).
  if (namesMinusYou.length === 1 && foundExact) {
    rawScore += 10000
  }

  if (rawScore && rawScore === insertionScore) {
    // insertionScore already penalizes long names, don't do it again below
    return rawScore
  }

  // We subtract inputLength to give a bonus to shorter groups, but we never want that to make a matching score go to zero
  const inputLength = searchStr.length

  return rawScore > 0 ? Math.max(1, rawScore - inputLength) : 0
}

const makeSmallItem = (meta, filter, you, insertMatcher) => {
  const s = score(filter, you, meta.teamname ? [meta.teamname] : meta.participants.toArray(), insertMatcher)
  return s > 0
    ? {
        data: {conversationIDKey: meta.conversationIDKey, type: 'small'},
        score: s,
        timestamp: meta.timestamp,
      }
    : null
}

const makeBigItem = (meta, filter, insertMatcher) => {
  const s = score(filter, '', [meta.teamname, meta.channelname].filter(Boolean), insertMatcher)
  return s > 0
    ? {
        data: {
          channelname: meta.channelname,
          conversationIDKey: meta.conversationIDKey,
          teamname: meta.teamname,
          type: 'big',
        },
        score: s,
        timestamp: 0,
      }
    : null
}

// Ignore headers, score based on matches of participants, ignore total non matches
const getFilteredRowsAndMetadata = memoize<Types.MetaMap, Types.ConversationCountMap, string, string, _>(
  (metaMap: Types.MetaMap, unread: Types.ConversationCountMap, filter: string, username: string) => {
    const metas = metaMap.valueSeq().toArray()
    let lcFilter = filter.toLowerCase()
    const lcYou = username.toLowerCase()
    let metasFiltered = metas
    if (lcFilter.startsWith('@unread')) {
      metasFiltered = metas.filter(m => unread.get(m.conversationIDKey, 0) > 0)
      lcFilter = lcFilter.substring('@unread'.length).trim()
    }
    const insertMatcher = new RegExp(
      `${lcFilter
        .replace(/ |#/g, '')
        .split('')
        .map(c => `${c}.*?`)
        .join('')}`,
      'i'
    )
    const rows: Array<RowItem> = metasFiltered
      .map(meta =>
        meta.teamType !== 'big'
          ? makeSmallItem(meta, lcFilter, lcYou, insertMatcher)
          : makeBigItem(meta, lcFilter, insertMatcher)
      )
      .filter(Boolean)
      .sort((a, b) => {
        return a.score === b.score ? b.timestamp - a.timestamp : b.score - a.score
      })
      .map(({data}) => (data: RowItem))

    return {
      allowShowFloatingButton: false,
      rows,
      smallTeamsExpanded: true,
    }
  }
)

export default getFilteredRowsAndMetadata

export const _testing = {
  score,
}
