// @flow
import * as React from 'react'
import * as Kb from '../../common-adapters'
import * as Styles from '../../styles'
import {SignupScreen} from '../common'

type Props = {|
  onBack: () => void,
  onChangeUsername: string => void,
  onContinue: () => void,
  onLogin: ?() => void,
|}

const EnterUsername = (props: Props) => (
  <SignupScreen
    buttons={[{label: 'Continue', onClick: props.onContinue, type: 'PrimaryGreen'}]}
    onBack={props.onBack}
    title={Styles.isMobile ? 'Create account' : 'Create an account'}
  >
    <Kb.Box2
      alignItems="center"
      gap={Styles.isMobile ? 'small' : 'medium'}
      direction="vertical"
      style={styles.body}
      fullWidth={true}
    >
      <Kb.Avatar size={96} />
      <Kb.Box2 direction="vertical" gap="tiny">
        <Kb.NewInput
          autoFocus={true}
          containerStyle={styles.input}
          placeholder="Pick a username"
          onChangeText={props.onChangeUsername}
        />
        <Kb.Text type="BodySmall" style={styles.inputSub}>
          Your username is unique and can not be changed in the future.
        </Kb.Text>
      </Kb.Box2>
    </Kb.Box2>
  </SignupScreen>
)

const styles = Styles.styleSheetCreate({
  body: {
    flex: 1,
  },
  input: Styles.platformStyles({
    common: {},
    isElectron: {
      ...Styles.padding(0, Styles.globalMargins.xsmall),
      height: 38,
      width: 368,
    },
    isMobile: {
      ...Styles.padding(0, Styles.globalMargins.small),
      height: 48,
    },
  }),
  inputSub: {
    marginLeft: 2,
  },
})

export default EnterUsername
